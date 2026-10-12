package kuaifan

import (
	"testing"

	"github.com/oshinop/chinadapter/internal/provider"
	wireprofile "github.com/oshinop/chinadapter/internal/provider/kuaifan/profile"
)

func TestNodeIDCanonicalPayloadAndLabelIndependence(t *testing.T) {
	route := provider.Route{Provider: ProviderID, Protocol: WIFIINProtocol, Host: "Node.Example.", Port: 11000}
	expected, err := provider.NodeID(route)
	if err != nil {
		t.Fatal(err)
	}
	source := Lines{Groups: []Group{{ID: "group", Name: "old group"}}, Lines: []Line{{GroupID: "group", Host: route.Host, Port: route.Port, Label: "old line", Eligible: true}}}
	first, err := nodesFromLines(source, wireprofile.IOSID)
	if err != nil {
		t.Fatal(err)
	}
	source.Groups[0].Name = "new group"
	source.Lines[0].GroupID = "other group"
	source.Lines[0].GroupName = "other display"
	source.Lines[0].Label = "new line"
	second, err := nodesFromLines(source, wireprofile.WindowsID)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 1 || len(second) != 1 || first[0].ID != expected || second[0].ID != expected {
		t.Fatal("display labels or account authority affect node identity")
	}
}
