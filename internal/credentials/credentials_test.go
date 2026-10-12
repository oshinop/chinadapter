package credentials

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/kfadapter/kfadapter/internal/provider"
)

func TestIdentityDerivationAndStrictUUIDPath(t *testing.T) {
	hash := bytes.Repeat([]byte{7}, 32)
	installation := "00112233445566778899aabbccddeeff"
	identity, err := New(hash, installation)
	if err != nil {
		t.Fatal(err)
	}
	reference := func(key []byte, message string) []byte {
		m := hmac.New(sha256.New, key)
		_, _ = m.Write([]byte(message))
		return m.Sum(nil)
	}
	instance := reference(hash, "kfadapter/instance/v3\x00"+installation)
	route := provider.Route{Provider: "kuaifan", Protocol: "kuaifan-wifiin", Host: "Node.Example.", Port: 11000}
	key, err := provider.NodeKey(route)
	if err != nil {
		t.Fatal(err)
	}
	if key != "kuaifan\x00kuaifan-wifiin\x00node.example\x0011000" {
		t.Fatal("incorrect node key")
	}
	credentials, ok := identity.Credentials(route)
	if !ok {
		t.Fatal("missing credentials")
	}
	expected := reference(instance, "kfadapter/socks-user/v3\x00"+key)
	if credentials.Username != "n_"+base64.RawURLEncoding.EncodeToString(expected[:12]) {
		t.Fatal("incorrect username derivation")
	}
	if !ValidUUID(identity.SubscriptionID()) || !ValidUUID(credentials.Password) || identity.SubscriptionID() == credentials.Password {
		t.Fatal("UUID derivation or domain separation failed")
	}
	if id, ok := ParseSubscriptionPath("/sub/" + identity.SubscriptionID()); !ok || id != identity.SubscriptionID() {
		t.Fatal("canonical path rejected")
	}
	for _, path := range []string{identity.SubscriptionID(), "/sub/" + strings.ToUpper(identity.SubscriptionID()), "/sub/" + identity.SubscriptionID() + "/", "/sub/%30" + identity.SubscriptionID()[1:], "/sub/00000000-0000-4000-8000-000000000000", "/sub/00000000-0000-8000-0000-000000000000"} {
		if _, ok := ParseSubscriptionPath(path); ok {
			t.Fatalf("accepted noncanonical path %q", path)
		}
	}
	if !identity.AuthenticatePassword(credentials.Password) || identity.AuthenticatePassword("incorrect") {
		t.Fatal("password authentication failed")
	}
	fresh, err := New(bytes.Repeat([]byte{8}, 32), installation)
	if err != nil {
		t.Fatal(err)
	}
	changed, _ := fresh.Credentials(route)
	if changed == credentials || fresh.SubscriptionID() == identity.SubscriptionID() || fresh.Password() == identity.Password() {
		t.Fatal("token verifier change did not rotate credentials")
	}
	uninitialized, err := New(nil, installation)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := uninitialized.Credentials(route); ok || uninitialized.SubscriptionID() != "" || uninitialized.AuthenticatePassword(credentials.Password) {
		t.Fatal("uninitialized installation exposes authority")
	}
}
