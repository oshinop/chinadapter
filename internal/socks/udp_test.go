package socks

import (
	"net/netip"
	"testing"
)

func TestValidUDPRequest(t *testing.T) {
	ipv4 := []byte{0, 0, 0, addressIPv4, 127, 0, 0, 1, 0, 53}
	ipv6 := make([]byte, 22)
	ipv6[3], ipv6[19], ipv6[21] = addressIPv6, 1, 53
	domain := []byte{0, 0, 0, addressDomain, 1, 'a', 0, 53}
	for _, test := range []struct {
		name   string
		packet []byte
		valid  bool
	}{
		{"ipv4", ipv4, true},
		{"ipv6", ipv6, true},
		{"domain", domain, true},
		{"payload", append(append([]byte(nil), ipv4...), 'x'), true},
		{"empty", nil, false},
		{"incomplete_header", ipv4[:3], false},
		{"incomplete_ipv4", ipv4[:9], false},
		{"incomplete_ipv6", ipv6[:21], false},
		{"missing_domain_length", domain[:4], false},
		{"incomplete_domain", domain[:7], false},
		{"empty_domain", []byte{0, 0, 0, addressDomain, 0, 0, 53}, false},
		{"unsupported_type", []byte{0, 0, 0, 0xff}, false},
		{"fragmented", []byte{0, 0, 1, addressIPv4, 127, 0, 0, 1, 0, 53}, false},
		{"reserved_high", []byte{1, 0, 0, addressIPv4, 127, 0, 0, 1, 0, 53}, false},
		{"reserved_low", []byte{0, 1, 0, addressIPv4, 127, 0, 0, 1, 0, 53}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if valid := validUDPRequest(test.packet); valid != test.valid {
				t.Fatalf("validUDPRequest(%x) = %t, want %t", test.packet, valid, test.valid)
			}
		})
	}
}

func TestUDPAssociationPinnedSourceDoesNotAllocate(t *testing.T) {
	address := netip.MustParseAddrPort("127.0.0.1:12345")
	association := &udpAssociation{clientIP: address.Addr()}
	if !association.acceptSource(address) {
		t.Fatal("initial source was not accepted")
	}
	var accepted bool
	allocations := testing.AllocsPerRun(100, func() {
		accepted = association.acceptSource(address)
	})
	if !accepted || allocations != 0 {
		t.Fatalf("pinned source accepted = %t, allocations = %g, want true, 0", accepted, allocations)
	}
}
