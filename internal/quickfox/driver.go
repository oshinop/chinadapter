package quickfox

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kfadapter/kfadapter/internal/identity"
	"github.com/kfadapter/kfadapter/internal/provider"
)

const (
	ProviderID     provider.ID       = "quickfox"
	NativeProtocol provider.Protocol = "quickfox-native"
	standardTier                     = "Standard"
	vipTier                          = "VIP"
	svipTier                         = "SVIP"

	maxCatalogGroups  = 32
	maxCatalogRegions = 512
	maxCatalogLines   = 4096
	maxMetadataBytes  = 512
	authorityID       = "native"
)

type DriverConfig struct {
	Client            *Client
	AuthorityLifetime time.Duration
	Clock             func() time.Time
}

// Driver owns one QuickFox account token and its complete native-relay catalog.
type Driver struct {
	client   *Client
	lifetime time.Duration
	clock    func() time.Time
}

func NewDriver(config DriverConfig) (*Driver, error) {
	if config.Client == nil {
		return nil, errors.New("quickfox: client is required")
	}
	lifetime := config.AuthorityLifetime
	if lifetime <= 0 || lifetime > 24*time.Hour {
		lifetime = 24 * time.Hour
	}
	clock := config.Clock
	if clock == nil {
		clock = config.Client.clock
	}
	if clock == nil {
		clock = time.Now
	}
	return &Driver{client: config.Client, lifetime: lifetime, clock: clock}, nil
}

func (*Driver) ID() provider.ID { return ProviderID }

func (driver *Driver) Login(ctx context.Context, credentials provider.Credentials) (provider.Snapshot, error) {
	if driver == nil || !credentials.Valid() {
		return provider.Snapshot{}, provider.ErrInvalidInput
	}
	session, err := driver.client.Login(ctx, credentials.Account, credentials.Password, credentials.InstallationID)
	credentials.Password = ""
	if err != nil {
		if errors.Is(err, ErrLoginRejected) {
			return provider.Snapshot{}, provider.ErrLoginRejected
		}
		return provider.Snapshot{}, err
	}
	catalog, err := driver.retryCatalog(ctx, session.Token, session.DeviceCode)
	if err != nil {
		return provider.Snapshot{}, err
	}
	if catalog.Profile.UserID != session.Profile.UserID {
		return provider.Snapshot{}, ErrSchema
	}
	return driver.snapshot(storedSession{Token: session.Token, UserID: session.Profile.UserID, DeviceCode: session.DeviceCode}, catalog)
}

func (driver *Driver) Refresh(ctx context.Context, current provider.Snapshot) (provider.Snapshot, error) {
	if driver == nil || current.Provider != ProviderID || !current.Valid() {
		return provider.Snapshot{}, provider.ErrNoSession
	}
	stored, err := decodeStoredSession(current.RefreshState)
	if err != nil {
		return provider.Snapshot{}, provider.ErrNoSession
	}
	catalog, err := driver.retryCatalog(ctx, stored.Token, stored.DeviceCode)
	if err != nil {
		return provider.Snapshot{}, err
	}
	if catalog.Profile.UserID != stored.UserID {
		return provider.Snapshot{}, provider.ErrNoSession
	}
	return driver.snapshot(stored, catalog)
}

type storedSession struct {
	Token      string `json:"token"`
	UserID     int64  `json:"userId"`
	DeviceCode string `json:"deviceCode"`
}

type tunnelAuthority struct {
	Token  string `json:"token"`
	UserID int64  `json:"userId"`
	AppID  uint32 `json:"appId"`
}

type vipPeriod struct {
	EndTime string `json:"endTime"`
	Grade   int    `json:"grade"`
}

type svipStatus struct {
	Time int64 `json:"svipTime"`
}

type accountPayload struct {
	Token           string      `json:"token"`
	UserID          int64       `json:"userId"`
	Email           string      `json:"email"`
	Username        string      `json:"username"`
	VIPTime         int64       `json:"vipTime,string"`
	SVIP            svipStatus  `json:"svip"`
	VIPSubscription []vipPeriod `json:"vipInfo"`
}

type loginResponse struct {
	accountPayload
}

func (payload accountPayload) account(location *time.Location, now time.Time) (provider.Account, error) {
	if payload.UserID <= 0 {
		return provider.Account{}, ErrSchema
	}
	identity := strings.TrimSpace(payload.Email)
	if identity == "" {
		identity = strings.TrimSpace(payload.Username)
	}
	if !validMetadata(identity) {
		return provider.Account{}, ErrSchema
	}
	tier := standardTier
	subscriptionGrade := 0
	if payload.SVIP.Time > 0 {
		tier = svipTier
		subscriptionGrade = 2
	} else if payload.VIPTime > 0 {
		tier = vipTier
		subscriptionGrade = 1
	}
	var subscriptionEndsAt time.Time
	for _, period := range payload.VIPSubscription {
		if period.Grade != 1 && period.Grade != 2 {
			return provider.Account{}, ErrSchema
		}
		if period.EndTime == "" {
			continue
		}
		parsed, err := time.ParseInLocation("2006-01-02 15:04:05", period.EndTime, location)
		if err != nil {
			return provider.Account{}, ErrSchema
		}
		if period.Grade == subscriptionGrade && parsed.After(subscriptionEndsAt) {
			subscriptionEndsAt = parsed.UTC()
		}
	}
	active := subscriptionGrade != 0
	if active && !subscriptionEndsAt.After(now) {
		return provider.Account{}, ErrSchema
	}
	return provider.Account{
		UserID: strconv.FormatInt(payload.UserID, 10), Display: provider.RedactAccount(identity), Tier: tier,
		SubscriptionActive: active, SubscriptionEndsAt: subscriptionEndsAt,
	}, nil
}

type lineGroup struct {
	TypeID   int          `json:"typeId"`
	TypeName string       `json:"typeName"`
	Regions  []lineRegion `json:"regionNameList"`
}

type lineRegion struct {
	RegionID *int       `json:"regionId"`
	Name     string     `json:"regionName"`
	Lines    []linePool `json:"linePoolList"`
}

type linePool struct {
	PoolID       int64  `json:"linePoolId"`
	Name         string `json:"lineName"`
	PoolName     string `json:"linePoolName"`
	ConnectIP    string `json:"connectIp"`
	ConnectPort  uint16 `json:"connectPort"`
	ProtocolType string `json:"protocolType"`
	FeeType      int    `json:"feeType"`
	Hidden       int    `json:"isHide"`
	Status       *int   `json:"status"`
}

func (driver *Driver) snapshot(stored storedSession, catalog catalog) (provider.Snapshot, error) {
	now := driver.clock().UTC()
	account, err := catalog.Profile.account(driver.client.location, now)
	if err != nil || account.UserID != strconv.FormatInt(stored.UserID, 10) {
		return provider.Snapshot{}, ErrSchema
	}
	nodes, err := nodesFromCatalog(catalog.Groups, account.Tier)
	if err != nil {
		return provider.Snapshot{}, err
	}
	stateBytes, err := json.Marshal(stored)
	if err != nil {
		return provider.Snapshot{}, ErrSchema
	}
	authorityBytes, err := json.Marshal(tunnelAuthority{Token: stored.Token, UserID: stored.UserID})
	if err != nil {
		return provider.Snapshot{}, ErrSchema
	}
	snapshot := provider.Snapshot{
		Provider: ProviderID, Account: account, ExpiresAt: now.Add(driver.lifetime), RefreshState: stateBytes,
		Authorities: map[string]provider.Authority{authorityID: {Protocol: NativeProtocol, Data: authorityBytes}}, Nodes: nodes,
	}
	if err := provider.ValidateSnapshot(snapshot, ProviderID, now); err != nil {
		return provider.Snapshot{}, err
	}
	return snapshot, nil
}

func nodesFromCatalog(groups []lineGroup, tier string) ([]provider.Node, error) {
	if len(groups) == 0 || len(groups) > maxCatalogGroups {
		return nil, ErrSchema
	}
	nodes := make([]provider.Node, 0, 512)
	seen := make(map[string]struct{}, 512)
	regionCount := 0
	lineCount := 0
	for _, group := range groups {
		if group.TypeID <= 0 || !validMetadata(group.TypeName) || len(group.Regions) > maxCatalogRegions-regionCount {
			return nil, ErrInvalidLine
		}
		regionCount += len(group.Regions)
		for _, region := range group.Regions {
			if !validMetadata(region.Name) || len(region.Lines) > maxCatalogLines-lineCount {
				return nil, ErrInvalidLine
			}
			lineCount += len(region.Lines)
			for _, line := range region.Lines {
				node, err := catalogNode(group, region, line, tier)
				if err != nil {
					return nil, err
				}
				if !node.Eligible {
					continue
				}
				if _, duplicate := seen[node.ID]; duplicate {
					continue
				}
				seen[node.ID] = struct{}{}
				nodes = append(nodes, node)
			}
		}
	}
	if lineCount == 0 || lineCount > maxCatalogLines {
		return nil, ErrInvalidLine
	}
	return nodes, nil
}

func catalogNode(group lineGroup, region lineRegion, line linePool, tier string) (provider.Node, error) {
	feeEligible, validFeeType := feeTypeEligible(tier, line.FeeType)
	if line.PoolID <= 0 || !validMetadata(line.Name) || !validMetadata(line.PoolName) || line.Name != line.PoolName ||
		line.ProtocolType != "socks" || line.Hidden != 0 || !validFeeType {
		return provider.Node{}, ErrInvalidLine
	}
	address, err := netip.ParseAddr(line.ConnectIP)
	if err != nil || !address.Is4() || address.String() != line.ConnectIP || line.ConnectPort == 0 {
		return provider.Node{}, ErrInvalidLine
	}
	id, err := identity.NodeID(identity.Route{Provider: ProviderID, Protocol: NativeProtocol, Host: line.ConnectIP, Port: line.ConnectPort})
	if err != nil {
		return provider.Node{}, fmt.Errorf("%w: node identity: %w", ErrInvalidLine, err)
	}
	eligible := (line.Status == nil || *line.Status == 1) && feeEligible
	return provider.Node{
		ID: id, AuthorityID: authorityID,
		Protocol: NativeProtocol, Host: line.ConnectIP, Port: line.ConnectPort, Name: line.Name,
		Group: group.TypeName + " / " + region.Name, Model: group.TypeName, Eligible: eligible,
	}, nil
}

func feeTypeEligible(tier string, feeType int) (bool, bool) {
	if tier != standardTier && tier != vipTier && tier != svipTier {
		return false, false
	}
	switch feeType {
	case 0:
		return true, true
	case 1, 2:
		return tier == vipTier || tier == svipTier, true
	case 3:
		return tier == svipTier, true
	default:
		return false, false
	}
}

func decodeStoredSession(encoded []byte) (storedSession, error) {
	var stored storedSession
	if len(encoded) == 0 || len(encoded) > 1<<20 || json.Unmarshal(encoded, &stored) != nil ||
		!validToken(stored.Token) || stored.UserID <= 0 || !validDeviceCode(stored.DeviceCode) {
		return storedSession{}, ErrSchema
	}
	return stored, nil
}

func decodeTunnelAuthority(encoded []byte) (tunnelAuthority, error) {
	var authority tunnelAuthority
	if len(encoded) == 0 || len(encoded) > 1<<20 || json.Unmarshal(encoded, &authority) != nil ||
		!validToken(authority.Token) || authority.UserID <= 0 || authority.UserID > int64(^uint32(0)) {
		return tunnelAuthority{}, ErrSchema
	}
	return authority, nil
}

func deviceCode(installationID string) (string, error) {
	raw, err := hex.DecodeString(installationID)
	if err != nil || len(raw) != 16 || hex.EncodeToString(raw) != installationID {
		return "", ErrSchema
	}
	raw[6] = raw[6]&0x0f | 0x40
	raw[8] = raw[8]&0x3f | 0x80
	encoded := hex.EncodeToString(raw)
	return fmt.Sprintf("%s-%s-%s-%s-%s", encoded[:8], encoded[8:12], encoded[12:16], encoded[16:20], encoded[20:]), nil
}

func validDeviceCode(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	raw := strings.ReplaceAll(value, "-", "")
	decoded, err := hex.DecodeString(raw)
	return err == nil && len(decoded) == 16 && decoded[6]>>4 == 4 && decoded[8]>>6 == 2 && hex.EncodeToString(decoded) == raw
}

func validToken(value string) bool {
	if len(value) == 0 || len(value) > 200 || !utf8.ValidString(value) || strings.ContainsAny(value, ",\x00") {
		return false
	}
	for _, character := range []byte(value) {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func validMetadata(value string) bool {
	return value != "" && len(value) <= maxMetadataBytes && utf8.ValidString(value) && strings.IndexByte(value, 0) < 0
}
