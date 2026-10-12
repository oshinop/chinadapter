package quickfox

import "testing"

func TestCatalogNodeCanonicalIdentity(t *testing.T) {
	status, regionID := 1, 30
	group := lineGroup{TypeID: 2, TypeName: "国内模式"}
	region := lineRegion{RegionID: &regionID, Name: "美国节点"}
	line := linePool{PoolID: 1191, Name: "洛杉矶自F区", PoolName: "洛杉矶自F区", ConnectIP: "117.24.248.147", ConnectPort: 443, ProtocolType: "socks", FeeType: 0, Status: &status}
	node, err := catalogNode(group, region, line, vipTier)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := node.ID, "quickfox_auLS0Ffo5ZPQc6Qv"; got != want {
		t.Fatalf("node ID = %q, want %q", got, want)
	}
	changed := line
	changed.PoolID++
	other, err := catalogNode(group, region, changed, vipTier)
	if err != nil {
		t.Fatal(err)
	}
	if other.ID != node.ID {
		t.Fatal("display pool ID must not affect canonical identity")
	}
}
