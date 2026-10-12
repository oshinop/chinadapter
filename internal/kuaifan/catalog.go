package kuaifan

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/kfadapter/kfadapter/internal/identity"
	wireprofile "github.com/kfadapter/kfadapter/internal/kuaifan/profile"
	"github.com/kfadapter/kfadapter/internal/provider"
)

func aggregateProviderAccount(display string, profiles [2]completeProfile, now time.Time) (provider.Account, error) {
	if display == "" {
		return provider.Account{}, ErrSchema
	}
	var userID int32
	active := true
	var subscriptionEndsAt time.Time
	for _, profile := range profiles {
		if profile.session.UserID <= 0 {
			continue
		}
		if userID != 0 && profile.session.UserID != userID {
			return provider.Account{}, ErrSchema
		}
		userID = profile.session.UserID
		active = active && profile.session.Profile.IsVIP
		if other := profile.session.Profile.VIPEndsAt; subscriptionEndsAt.IsZero() || !other.IsZero() && other.Before(subscriptionEndsAt) {
			subscriptionEndsAt = other
		}
	}
	if userID <= 0 || active && subscriptionEndsAt.IsZero() {
		return provider.Account{}, ErrSchema
	}
	active = active && subscriptionEndsAt.After(now)
	tier := standardTier
	if active {
		tier = vipTier
	} else {
		subscriptionEndsAt = time.Time{}
	}
	return provider.Account{
		UserID: formatUserID(userID), Display: display, Tier: tier,
		SubscriptionActive: active, SubscriptionEndsAt: subscriptionEndsAt,
	}, nil
}

type tunnelAuthority struct {
	Password  string `json:"password"`
	Method    string `json:"method"`
	Extension string `json:"extension"`
}

func (driver *Driver) snapshot(profiles [2]completeProfile, account provider.Account, stored driverState) (provider.Snapshot, error) {
	stateBytes, err := json.Marshal(stored)
	if err != nil {
		return provider.Snapshot{}, ErrSchema
	}
	authorities := make(map[string]provider.Authority, len(profiles))
	for _, profile := range profiles {
		if profile.client == nil {
			continue
		}
		encoded, err := json.Marshal(tunnelAuthority{
			Password: profile.authority.EncryptKey, Method: profile.authority.EncryptType, Extension: profile.authority.ProviderExtension,
		})
		if err != nil {
			return provider.Snapshot{}, ErrSchema
		}
		authorities[string(profile.client.Profile())] = provider.Authority{Protocol: WIFIINProtocol, Data: encoded}
	}
	iosNodes, err := nodesFromLines(profiles[0].lines, wireprofile.IOSID)
	if err != nil {
		return provider.Snapshot{}, err
	}
	windowsNodes, err := nodesFromLines(profiles[1].lines, wireprofile.WindowsID)
	if err != nil {
		return provider.Snapshot{}, err
	}
	now := driver.now().UTC()
	snapshot := provider.Snapshot{
		Provider: ProviderID, Account: account, ExpiresAt: now.Add(driver.lifetime), RefreshState: stateBytes,
		Authorities: authorities, Nodes: mergeProfileNodes(iosNodes, windowsNodes),
	}
	if err := provider.ValidateSnapshot(snapshot, ProviderID, now); err != nil {
		return provider.Snapshot{}, err
	}
	return snapshot, nil
}

func decodeTunnelAuthority(encoded []byte) (tunnelAuthority, error) {
	var authority tunnelAuthority
	if len(encoded) == 0 || len(encoded) > 1<<20 || json.Unmarshal(encoded, &authority) != nil ||
		authority.Password == "" || authority.Method != "aes-256-cfb" || authority.Extension == "" {
		return tunnelAuthority{}, ErrInvalidAuthority
	}
	return authority, nil
}

func mergeProfileNodes(ios, windows []provider.Node) []provider.Node {
	merged := make([]provider.Node, 0, len(ios)+len(windows))
	seen := make(map[string]struct{}, len(ios)+len(windows))
	for _, profileNodes := range [][]provider.Node{ios, windows} {
		for _, node := range profileNodes {
			if _, duplicate := seen[node.ID]; duplicate {
				continue
			}
			seen[node.ID] = struct{}{}
			merged = append(merged, node)
		}
	}
	return merged
}

func nodesFromLines(lines Lines, profileID wireprofile.ID) ([]provider.Node, error) {
	if profileID != wireprofile.IOSID && profileID != wireprofile.WindowsID {
		return nil, ErrSchema
	}
	groups := make(map[string]string, len(lines.Groups))
	for _, group := range lines.Groups {
		groups[group.ID] = group.Name
	}
	seen := make(map[string]struct{}, len(lines.Lines))
	nodes := make([]provider.Node, 0, len(lines.Lines))
	for _, line := range lines.Lines {
		if !line.Eligible {
			continue
		}
		route, err := identity.Canonicalize(identity.Route{Provider: ProviderID, Protocol: WIFIINProtocol, Host: line.Host, Port: line.Port})
		if err != nil {
			return nil, fmt.Errorf("%w: canonical node identity: %w", ErrSchema, err)
		}
		id, err := identity.NodeID(route)
		if err != nil {
			return nil, fmt.Errorf("%w: node identity: %w", ErrSchema, err)
		}
		if _, duplicate := seen[id]; duplicate {
			continue
		}
		seen[id] = struct{}{}
		groupName := line.GroupName
		if groupName == "" {
			groupName = groups[line.GroupID]
		}
		nodes = append(nodes, provider.Node{
			ID: id, AuthorityID: string(profileID), Protocol: WIFIINProtocol, Host: route.Host, Port: route.Port,
			Name: line.Label, Group: groupName, Model: line.Model, Weight: line.Weight, Auto: line.Auto, Eligible: line.Eligible,
		})
	}
	return nodes, nil
}
