package profile

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

const (
	WindowsUserAgent = "SPEEDIN"
	WindowsOS        = "WINDOWS"
	WindowsEdition   = "INTERNATIONAL"
	// WindowsOSVersion is a synthetic Windows product version; no host hardware
	// or host OS fingerprint is read by the adapter.
	WindowsOSVersion     = "10.0"
	WindowsManufacture   = "Microsoft Corporation"
	WindowsClientVersion = "4.7.6"
	WindowsPromoPlatform = "speedin.cc"
	WindowsDeviceType    = "WINDOWS"
	WindowsTunnelMethod  = "aes-128-gcm"
)

// Windows is the recovered Windows 4.7.6 beta INTERNATIONAL wire profile.
type Windows struct{}

func (Windows) ID() ID                         { return WindowsID }
func (Windows) UserAgent() string              { return WindowsUserAgent }
func (Windows) ConfigFields() any              { return map[string]any{"os": WindowsOS} }
func (Windows) RequiresPostLoginRefresh() bool { return false }
func (Windows) ValidateLine(provider, password string) (bool, error) {
	if provider != "SPEEDIN" {
		return false, nil
	}
	if password == "" || !withinLimit(password) {
		return false, ErrInvalidLine
	}
	return true, nil
}

// WindowsLoginFields is exactly the recovered beta email/password schema.
type WindowsLoginFields struct {
	Time              string `json:"time"`
	Lang              string `json:"lang"`
	Nonce             string `json:"nonce"`
	DeviceID          string `json:"deviceId"`
	MAC               string `json:"mac"`
	UDID              string `json:"udid"`
	OpenUDID          string `json:"openUdid"`
	OSVersion         string `json:"osVersion"`
	Manufacture       string `json:"manufacture"`
	DeviceType        string `json:"deviceType"`
	Account           string `json:"account"`
	Password          string `json:"password"`
	OS                string `json:"os"`
	Edition           string `json:"edition"`
	ClientVersion     string `json:"clientVersion"`
	PromoPlatformCode string `json:"promoPlatformCode"`
	Verify            string `json:"verify"`
	LoginType         int    `json:"loginType"`
}

// ClearPassword drops the transient request-field reference after encoding.
func (fields *WindowsLoginFields) ClearPassword() {
	if fields != nil {
		fields.Password = ""
	}
}

// ComputeWindowsVerify implements the recovered Windows login verifier over
// the synthetic MAC and request timestamp.
func ComputeWindowsVerify(mac, timestamp string, randomness io.Reader) (string, error) {
	if len(timestamp) < 17 {
		return "", ErrInvalidVerifyInput
	}
	return computeVerify(mac, timestamp, randomness, validWindowsMAC)
}

// BuildLoginFields builds the Windows request from protected random
// installation state rather than host hardware identifiers.
func (Windows) BuildLoginFields(input LoginInput, timestamp, language string, randomness io.Reader) (*WindowsLoginFields, error) {
	if !withinLimit(input.Account) || !withinLimit(input.Password) || !withinLimit(language) || strings.TrimSpace(input.Account) == "" || input.Password == "" || strings.TrimSpace(language) == "" {
		return nil, ErrInvalidVerifyInput
	}
	deviceID, err := windowsDeviceGUID(input.InstallationID)
	if err != nil {
		return nil, err
	}
	if randomness == nil {
		randomness = rand.Reader
	}
	nonce, err := RandomInt(randomness, 100000000)
	if err != nil {
		return nil, fmt.Errorf("control profile: generate nonce: %w", err)
	}
	verify, err := ComputeWindowsVerify(DefaultSyntheticMAC, timestamp, randomness)
	if err != nil {
		return nil, err
	}
	return &WindowsLoginFields{
		Account: input.Account, LoginType: 4, Password: input.Password, DeviceID: deviceID,
		MAC: DefaultSyntheticMAC, UDID: deviceID, OpenUDID: deviceID,
		OS: WindowsOS, OSVersion: WindowsOSVersion, Manufacture: WindowsManufacture, DeviceType: WindowsDeviceType,
		ClientVersion: WindowsClientVersion, PromoPlatformCode: WindowsPromoPlatform,
		Time: timestamp, Verify: verify, Lang: language,
		Edition: WindowsEdition, Nonce: fmt.Sprintf("%08d", nonce),
	}, nil
}

func windowsDeviceGUID(installationID string) (string, error) {
	raw, err := hex.DecodeString(installationID)
	if err != nil || len(raw) != 16 || hex.EncodeToString(raw) != installationID {
		return "", ErrInvalidVerifyInput
	}
	raw[6] = raw[6]&0x0f | 0x40
	raw[8] = raw[8]&0x3f | 0x80
	encoded := hex.EncodeToString(raw)
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:], nil
}

func validWindowsMAC(mac string) bool {
	if len(mac) != 12 {
		return false
	}
	for _, value := range mac {
		if (value < '0' || value > '9') && (value < 'A' || value > 'F') {
			return false
		}
	}
	return true
}
