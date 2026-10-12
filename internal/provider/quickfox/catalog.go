package quickfox

import (
	"fmt"
	"net/netip"

	"github.com/kfadapter/kfadapter/internal/provider"
)

type catalog struct {
	Profile accountPayload `json:"userInfo"`
	Groups  []lineGroup    `json:"lineList"`
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
	id, err := provider.NodeID(provider.Route{Provider: ProviderID, Protocol: NativeProtocol, Host: line.ConnectIP, Port: line.ConnectPort})
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
