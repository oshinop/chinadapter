package provider

import "testing"

func TestCanonicalRouteAndProtocolSeparation(t *testing.T) {
	route := Route{Provider: "quickfox", Protocol: "quickfox-native", Host: "2001:0db8::1", Port: 443}
	canonical, err := Canonicalize(route)
	if err != nil {
		t.Fatal(err)
	}
	if canonical.Host != "2001:db8::1" {
		t.Fatal("IP not canonicalized")
	}
	first, err := NodeID(route)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NodeID(canonical)
	if err != nil || first != second {
		t.Fatal("canonical route changed ID")
	}
	canonical.Protocol = "other-native"
	third, err := NodeID(canonical)
	if err != nil || first == third {
		t.Fatal("protocol omitted from ID")
	}
}
