package web

import "testing"

func TestValidAccountAcceptsEmailOrPhoneOnly(t *testing.T) {
	t.Parallel()
	for account, want := range map[string]bool{
		"person@example.com":          true,
		"13800138000":                 true,
		"+8613800138000":              true,
		"12345":                       false,
		"123456789012345678901":       false,
		"138-0013-8000":               false,
		"++8613800138000":             false,
		"Person <person@example.com>": false,
		"person@":                     false,
		"person\r\n@example.com":      false,
		"":                            false,
	} {
		if got := validAccount(account); got != want {
			t.Errorf("validAccount(%q) = %v, want %v", account, got, want)
		}
	}
}
