package quickfox

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/kfadapter/kfadapter/internal/provider"
)

func TestDriverLoginRejectsUserIDAboveUint32Maximum(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name     string
		userID   int64
		rejected bool
	}{
		{name: "maximum", userID: int64(^uint32(0))},
		{name: "maximum plus one", userID: int64(^uint32(0)) + 1, rejected: true},
		{name: "maximum int64", userID: int64(^uint64(0) >> 1), rejected: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			driver := userIDTestDriver(t, test.userID)
			snapshot, err := driver.Login(context.Background(), provider.Credentials{
				Account: "alice@example.com", Password: "password", InstallationID: "00112233445566778899aabbccddeeff",
			})
			if test.rejected {
				if !errors.Is(err, ErrSchema) || !strings.Contains(err.Error(), "user ID exceeds uint32 maximum") || !reflect.DeepEqual(snapshot, provider.Snapshot{}) {
					t.Fatalf("oversized user ID: snapshot published %t, error %v", !reflect.DeepEqual(snapshot, provider.Snapshot{}), err)
				}
				return
			}
			if err != nil || !snapshot.Valid() || snapshot.Account.UserID != strconv.FormatInt(test.userID, 10) {
				t.Fatalf("maximum user ID: snapshot valid %t, error %v", snapshot.Valid(), err)
			}
			var authority tunnelAuthority
			if err := json.Unmarshal(snapshot.Authorities[authorityID].Data, &authority); err != nil {
				t.Fatal(err)
			}
			if _, err := encodeTunnelAuth(authority, 0, 0x20, netip.Addr{}, 0); err != nil {
				t.Fatalf("maximum user ID tunnel authority: %v", err)
			}
		})
	}
}

func TestDriverRefreshRejectsLegacyUserIDAboveUint32Maximum(t *testing.T) {
	t.Parallel()
	userID := int64(^uint32(0)) + 1
	driver := userIDTestDriver(t, userID)
	current := refreshTestSnapshot(t, driver)
	stored, err := decodeStoredSession(current.RefreshState)
	if err != nil {
		t.Fatal(err)
	}
	stored.UserID = userID
	current.RefreshState, err = json.Marshal(stored)
	if err != nil {
		t.Fatal(err)
	}
	authority := current.Authorities[authorityID]
	authority.Data, err = json.Marshal(tunnelAuthority{Token: stored.Token, UserID: userID})
	if err != nil {
		t.Fatal(err)
	}
	current.Authorities[authorityID] = authority
	current.Account.UserID = strconv.FormatInt(userID, 10)
	if !current.Valid() {
		t.Fatal("legacy snapshot fixture must be structurally valid")
	}
	before := current.Clone()
	next, err := driver.Refresh(context.Background(), current)
	if !errors.Is(err, ErrSchema) || !strings.Contains(err.Error(), "user ID exceeds uint32 maximum") || !reflect.DeepEqual(next, provider.Snapshot{}) {
		t.Fatalf("legacy user ID refresh: snapshot published %t, error %v", !reflect.DeepEqual(next, provider.Snapshot{}), err)
	}
	if !reflect.DeepEqual(current, before) {
		t.Fatal("rejected refresh changed the caller snapshot")
	}
}

func userIDTestDriver(t *testing.T, userID int64) *Driver {
	t.Helper()
	fixture := catalogFixture()
	fixture.Profile.UserID = userID
	client := loopbackControlClient(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/user/login":
			profile := fixture.Profile
			profile.Token = "0123456789abcdef0123456789abcdef"
			writeEncryptedResponse(t, writer, profile)
		case "/user/info":
			writeEncryptedResponse(t, writer, fixture.Profile)
		case "/line/socksServerPoolList":
			writeEncryptedResponse(t, writer, fixture)
		default:
			http.NotFound(writer, request)
		}
	}))
	driver, err := NewDriver(DriverConfig{Client: client})
	if err != nil {
		t.Fatal(err)
	}
	return driver
}
