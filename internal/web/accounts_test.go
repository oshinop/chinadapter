package web

import (
	"strings"
	"testing"
)

func TestValidCredentialFieldsBoundsShapeOnly(t *testing.T) {
	t.Parallel()
	tooMany := make(map[string]string, maxCredentialFields+1)
	for index := range maxCredentialFields + 1 {
		tooMany["k"+strings.Repeat("x", index)] = "v"
	}
	for name, test := range map[string]struct {
		fields map[string]string
		want   bool
	}{
		"public provider sends nothing": {nil, true},
		"account and password":          {map[string]string{"account": "13800138000", "password": "secret"}, true},
		"arbitrary declared key":        {map[string]string{"region": "cn"}, true},
		"empty value left to the spec":  {map[string]string{"account": ""}, true},
		"too many fields":               {tooMany, false},
		"non-identifier key":            {map[string]string{"Account": "x"}, false},
		"oversized value":               {map[string]string{"account": strings.Repeat("x", 4097)}, false},
		"NUL in value":                  {map[string]string{"account": "a\x00b"}, false},
		"invalid UTF-8":                 {map[string]string{"account": "\xff"}, false},
	} {
		if got := validCredentialFields(test.fields); got != test.want {
			t.Errorf("%s: validCredentialFields = %v, want %v", name, got, test.want)
		}
	}
}
