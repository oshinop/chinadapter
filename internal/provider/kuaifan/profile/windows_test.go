package profile

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

func TestComputeWindowsVerifyGolden(t *testing.T) {
	t.Parallel()
	verify, err := ComputeWindowsVerify(
		"020000000000",
		"20260721042157621",
		bytes.NewReader([]byte{15, 14, 22, 49}),
	)
	if err != nil {
		t.Fatal(err)
	}
	const golden = "MjQzYTgyYzOWxMViNzk3NmE1NGVkMWUwNGExNzg4ZWMyOTY="
	if verify != golden {
		t.Fatalf("verify = %q, want %q", verify, golden)
	}
}

func TestWindowsLoginFieldsMatchRecoveredProfile(t *testing.T) {
	t.Parallel()
	const installationID = "0123456789abcdef0123456789abcdef"
	const deviceID = "01234567-89ab-4def-8123-456789abcdef"
	fields, err := (Windows{}).BuildLoginFields(LoginInput{
		Account: "person@example.test", Password: "not-persisted", InstallationID: installationID,
	}, "20260715101112123", "zh-CN", bytes.NewReader(make([]byte, 8)))
	if err != nil {
		t.Fatal(err)
	}
	if fields.DeviceID != deviceID || fields.UDID != deviceID || fields.OpenUDID != deviceID {
		t.Fatalf("unexpected synthetic identifiers: %#v", fields)
	}
	wantVerify, err := ComputeWindowsVerify(DefaultSyntheticMAC, "20260715101112123", bytes.NewReader([]byte{0, 0, 0, 0}))
	if err != nil {
		t.Fatal(err)
	}
	if fields.Verify != wantVerify || fields.LoginType != 4 || fields.MAC != DefaultSyntheticMAC {
		t.Fatalf("unexpected Windows login fields: %#v", fields)
	}
	if fields.OS != "WINDOWS" || fields.Edition != "INTERNATIONAL" || fields.OSVersion != WindowsOSVersion || fields.Manufacture != "Microsoft Corporation" || fields.DeviceType != "WINDOWS" || fields.ClientVersion != "4.7.6" || fields.PromoPlatformCode != "speedin.cc" || fields.Nonce != "00000000" {
		t.Fatalf("unexpected Windows profile constants: %#v", fields)
	}
	wire, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(wire, &object); err != nil {
		t.Fatal(err)
	}
	keys := []string{"time", "lang", "nonce", "deviceId", "mac", "udid", "openUdid", "osVersion", "manufacture", "deviceType", "account", "password", "os", "edition", "clientVersion", "promoPlatformCode", "verify", "loginType"}
	if len(object) != len(keys) {
		t.Fatalf("beta login has %d fields, want %d", len(object), len(keys))
	}
	for _, key := range keys {
		if _, exists := object[key]; !exists {
			t.Errorf("beta login missing %s", key)
		}
	}
}

func TestWindowsDefinition(t *testing.T) {
	t.Parallel()
	definition := Windows{}
	if definition.ID() != WindowsID || definition.UserAgent() != WindowsUserAgent || definition.RequiresPostLoginRefresh() {
		t.Fatalf("Windows definition = %#v", definition)
	}
	if eligible, err := definition.ValidateLine("SPEEDIN", "per-line-password"); err != nil || !eligible {
		t.Fatalf("Windows SPEEDIN eligibility = %t, %v", eligible, err)
	}
	if eligible, err := definition.ValidateLine("WS", ""); err != nil || eligible {
		t.Fatalf("Windows WS eligibility = %t, %v", eligible, err)
	}
	if eligible, err := definition.ValidateLine("FUTURE", ""); err != nil || eligible {
		t.Fatalf("unknown Windows provider eligibility = %t, %v", eligible, err)
	}
	if eligible, err := definition.ValidateLine("SPEEDIN", ""); !errors.Is(err, ErrInvalidLine) || eligible {
		t.Fatalf("malformed Windows SPEEDIN line = %t, %v", eligible, err)
	}
}

func TestWindowsVerifyRejectsShortTimestamp(t *testing.T) {
	if _, err := ComputeWindowsVerify(DefaultSyntheticMAC, "1234", bytes.NewReader(nil)); !errors.Is(err, ErrInvalidVerifyInput) {
		t.Fatalf("short timestamp error = %v", err)
	}
}

func TestWindowsLoginRejectsFailedNonceRandomness(t *testing.T) {
	if _, err := (Windows{}).BuildLoginFields(LoginInput{
		Account: "person@example.test", Password: "password", InstallationID: "0123456789abcdef0123456789abcdef",
	}, "20260715101112123", "zh-CN", bytes.NewReader(nil)); err == nil {
		t.Fatal("login accepted failed nonce randomness")
	}
}
