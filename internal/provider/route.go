package provider

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

var ErrInvalidIdentity = errors.New("invalid node identity")

var lookupIDNA = idna.New(idna.MapForLookup(), idna.StrictDomainName(true), idna.ValidateForRegistration(), idna.VerifyDNSLength(true))

// Route contains exactly the node inputs consumed by the current transports.
// Account authority is pinned independently; labels, weight, model and profile
// selection are not part of the route and must never change its credentials.
type Route struct {
	Provider ID
	Protocol Protocol
	Host     string
	Port     uint16
}

func Canonicalize(route Route) (Route, error) {
	if !route.Provider.Valid() || !route.Protocol.Valid() || route.Port == 0 || route.Host == "" || strings.IndexByte(route.Host, 0) >= 0 {
		return Route{}, ErrInvalidIdentity
	}
	if address, err := netip.ParseAddr(route.Host); err == nil {
		route.Host = address.String()
	} else {
		ascii, err := lookupIDNA.ToASCII(strings.TrimSuffix(strings.ToLower(route.Host), "."))
		if err != nil {
			return Route{}, fmt.Errorf("%w: canonical host: %w", ErrInvalidIdentity, err)
		}
		route.Host = strings.ToLower(ascii)
		if route.Host == "" || strings.ContainsAny(route.Host, "\x00/\\@:") {
			return Route{}, ErrInvalidIdentity
		}
	}
	return route, nil
}

// NodeKey is the canonical, unambiguous route encoding. Neither current
// transport consumes any additional per-node routing fields.
func NodeKey(route Route) (string, error) {
	route, err := Canonicalize(route)
	if err != nil {
		return "", err
	}
	return string(route.Provider) + "\x00" + string(route.Protocol) + "\x00" + route.Host + "\x00" + strconv.Itoa(int(route.Port)), nil
}

func NodeID(route Route) (string, error) {
	key, err := NodeKey(route)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(key))
	return string(route.Provider) + "_" + base64.RawURLEncoding.EncodeToString(digest[:12]), nil
}
