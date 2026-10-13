package provider

import (
	"errors"
	"testing"
)

func TestValidateCredentialsFollowsTheDriverSpec(t *testing.T) {
	t.Parallel()
	accountPassword := AccountPasswordAuth("Email")
	for name, test := range map[string]struct {
		spec        AuthSpec
		credentials Credentials
		ok          bool
	}{
		"public provider with no fields":       {AuthSpec{}, Credentials{InstallationID: "install"}, true},
		"public provider rejects stray fields": {AuthSpec{}, Credentials{InstallationID: "install", Fields: map[string]string{FieldAccount: "a"}}, false},
		"account and password":                 {accountPassword, Credentials{InstallationID: "install", Fields: map[string]string{FieldAccount: "a@example.com", FieldPassword: "pw"}}, true},
		"missing password":                     {accountPassword, Credentials{InstallationID: "install", Fields: map[string]string{FieldAccount: "a@example.com"}}, false},
		"blank account":                        {accountPassword, Credentials{InstallationID: "install", Fields: map[string]string{FieldAccount: "   ", FieldPassword: "pw"}}, false},
		"whitespace password is a value":       {accountPassword, Credentials{InstallationID: "install", Fields: map[string]string{FieldAccount: "a", FieldPassword: "  "}}, true},
		"extra field beyond spec":              {accountPassword, Credentials{InstallationID: "install", Fields: map[string]string{FieldAccount: "a", FieldPassword: "pw", "region": "cn"}}, false},
		"three-field provider":                 {AuthSpec{Fields: []AuthField{{Key: "token"}, {Key: "region"}, {Key: "pin", Secret: true}}}, Credentials{InstallationID: "install", Fields: map[string]string{"token": "t", "region": "cn", "pin": "1"}}, true},
		"missing installation ID":              {AuthSpec{}, Credentials{}, false},
	} {
		err := ValidateCredentials(test.spec, test.credentials)
		if test.ok && err != nil || !test.ok && !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%s: ValidateCredentials = %v, want ok=%v", name, err, test.ok)
		}
	}
}
