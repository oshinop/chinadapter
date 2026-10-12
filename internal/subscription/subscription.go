// Package subscription renders and serves local SOCKS5 subscriptions.
package subscription

import (
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/kfadapter/kfadapter/internal/config"
	"github.com/kfadapter/kfadapter/internal/identity"
	"github.com/kfadapter/kfadapter/internal/provider"
	"github.com/kfadapter/kfadapter/internal/state"
)

const (
	// MaxRenderedBytes bounds one subscription response body.
	MaxRenderedBytes = 10 << 20
)

var (
	ErrNoEligibleLinks         = errors.New("subscription has no eligible links")
	ErrRenderedTooLarge        = errors.New("subscription exceeds response size limit")
	ErrSubscriptionUnavailable = errors.New("subscription is not activated")
	ErrInvalidAddress          = errors.New("subscription SOCKS address must contain a canonical numeric IP address and port")
)

type link struct {
	Username string
	Password string
	Name     string
	Group    string
}

// Filter selects presentation rows without participating in node identity.
type Filter struct {
	Provider provider.ID
	Group    string
	Name     string
}

// Metadata is safe for the ordinary authenticated browser API. It intentionally
// contains neither the stable URL token nor derived SOCKS credentials.
type Metadata struct {
	Active    bool `json:"active"`
	NodeCount int  `json:"nodeCount"`
}

// Render emits padded Base64 of deterministic newline-delimited SOCKS5 links.
// Its complete input is request-local or immutable; it has no side effects.
func Render(nodes []state.Node, filter Filter, socksAddress string, authority *identity.Identity) (string, int, error) {
	host, port, err := parseAddress(socksAddress)
	if err != nil {
		return "", 0, err
	}
	eligible := make([]link, 0, len(nodes))
	foldedName := strings.ToLower(filter.Name)
	for _, node := range nodes {
		if !node.TunnelEligible() || node.Excluded || filter.Provider != "" && node.Provider != filter.Provider || filter.Group != "" && node.Group != filter.Group || foldedName != "" && !strings.Contains(strings.ToLower(node.Name), foldedName) {
			continue
		}
		credentials, available := authority.Credentials(node.Route())
		if !available {
			return "", 0, ErrSubscriptionUnavailable
		}
		eligible = append(eligible, link{Username: credentials.Username, Password: credentials.Password, Name: node.Name, Group: node.Group})
	}
	if len(eligible) == 0 {
		return "", 0, ErrNoEligibleLinks
	}
	sort.Slice(eligible, func(i, j int) bool {
		if eligible[i].Group != eligible[j].Group {
			return eligible[i].Group < eligible[j].Group
		}
		if eligible[i].Name != eligible[j].Name {
			return eligible[i].Name < eligible[j].Name
		}
		return eligible[i].Username < eligible[j].Username
	})
	var text strings.Builder
	for _, link := range eligible {
		u := &url.URL{
			Scheme: "socks5", User: url.UserPassword(link.Username, link.Password),
			Host: net.JoinHostPort(host, port), Fragment: link.Name,
		}
		text.WriteString(u.String())
		text.WriteByte('\n')
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(text.String()))
	if len(encoded) > MaxRenderedBytes {
		return "", 0, ErrRenderedTooLarge
	}
	return encoded, len(eligible), nil
}

func parseAddress(address string) (string, string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", "", ErrInvalidAddress
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNumber == 0 || strconv.FormatUint(portNumber, 10) != port {
		return "", "", ErrInvalidAddress
	}
	ip, err := netip.ParseAddr(host)
	if err == nil && ip.Zone() == "" && ip.String() == host {
		return ip.String(), port, nil
	}
	if config.ValidateHostname(host) != nil {
		return "", "", ErrInvalidAddress
	}
	return host, port, nil
}

func validateAddress(address string) error {
	_, _, err := parseAddress(address)
	return err
}

func subscriptionURL(baseURL, binding string) string {
	return strings.TrimRight(baseURL, "/") + "/sub/" + binding
}

func writeNotFound(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Length", "0")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusNotFound)
}
