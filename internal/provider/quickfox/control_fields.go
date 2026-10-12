package quickfox

import (
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf8"
)

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

func validControlString(value string) bool {
	return value != "" && len(value) <= maxControlFieldSize && strings.IndexByte(value, 0) < 0
}
