package transocks

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/oshinop/chinadapter/internal/provider"
)

const maxCatalogLines = 4096

type accountPayload struct {
	UserID             int64  `json:"user_id"`
	Email              string `json:"email"`
	Phone              string `json:"phone"`
	Expired            *bool  `json:"expired"`
	ExpireAt           string `json:"expire_at"`
	ExpireAtTime       int64  `json:"expire_at_time"`
	IsProUser          *bool  `json:"is_pro_user"`
	IsDeviceLogin      *bool  `json:"is_device_login"`
	IsRealname         *bool  `json:"is_realname"`
	PasswordSetup      *bool  `json:"password_setup"`
	RealnameGraceState *int   `json:"realname_grace_state"`
}

func (payload accountPayload) account(display string, now time.Time) (provider.Account, error) {
	if payload.UserID <= 0 || payload.Expired == nil {
		return provider.Account{}, ErrSchema
	}
	if payload.Email != "" {
		if !validControlField(payload.Email) {
			return provider.Account{}, ErrSchema
		}
		display = provider.RedactAccount(payload.Email)
	}
	if display == "" {
		display = "•••"
	}
	active := !*payload.Expired
	tier := "Free"
	var expiry time.Time
	if active {
		if payload.IsProUser != nil && *payload.IsProUser {
			tier = "Pro"
		} else {
			tier = "VIP"
		}
		if payload.ExpireAtTime > 0 {
			expiry = time.Unix(payload.ExpireAtTime, 0).UTC()
		} else {
			location := time.FixedZone("Asia/Shanghai", 8*60*60)
			for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05", "2006-01-02"} {
				parsed, err := time.ParseInLocation(layout, payload.ExpireAt, location)
				if err == nil {
					expiry = parsed.UTC()
					break
				}
			}
		}
		if !expiry.After(now) {
			return provider.Account{}, ErrSchema
		}
	}
	account := provider.Account{UserID: strconv.FormatInt(payload.UserID, 10), Display: display, Tier: tier, SubscriptionActive: active, SubscriptionEndsAt: expiry}
	if !account.Valid() {
		return provider.Account{}, ErrSchema
	}
	return account, nil
}

func (payload accountPayload) permitsConnections() bool {
	// Mirror explicit client gates without inventing missing nullable values.
	if payload.IsRealname != nil && !*payload.IsRealname && (payload.RealnameGraceState == nil || *payload.RealnameGraceState != 1) {
		return false
	}
	if payload.PasswordSetup != nil && !*payload.PasswordSetup && (payload.Email != "" || payload.Phone != "") {
		return false
	}
	return true
}

type catalog struct {
	Lines []line `json:"lines"`
}

type line struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	EnglishName string `json:"enName"`
	Category    string `json:"category"`
	Location    string `json:"location"`
	Free        bool   `json:"isFree"`
	Domain      string `json:"domain"`
	IPAddr      string `json:"iPAddr"`
	DetectPort  *int   `json:"detectPort"`
}

func (catalog catalog) validate() error {
	if len(catalog.Lines) == 0 || len(catalog.Lines) > maxCatalogLines {
		return ErrSchema
	}
	seen := make(map[int64]struct{}, len(catalog.Lines))
	for _, line := range catalog.Lines {
		if line.ID == 0 || line.ID < -2 || !validControlField(line.Name) || len(line.Category) > maxAuthorityField || len(line.Location) > maxAuthorityField {
			return ErrSchema
		}
		if _, duplicate := seen[line.ID]; duplicate {
			return ErrSchema
		}
		seen[line.ID] = struct{}{}
	}
	return nil
}

func (line line) eligible(profile accountPayload, account provider.Account) bool {
	return line.ID > 0 && profile.permitsConnections() && (line.Free || account.SubscriptionActive)
}

func (line line) group() string {
	parts := make([]string, 0, 2)
	for _, part := range []string{line.Category, line.Location} {
		if part = strings.TrimSpace(part); part != "" && (len(parts) == 0 || parts[0] != part) {
			parts = append(parts, part)
		}
	}
	return strings.Join(parts, " / ")
}

// probeAddress is the catalog detect endpoint the official client pings, or ""
// when the line advertises none. It never opens a tunnel or uses a connect slot.
func (line line) probeAddress() string {
	host := strings.TrimSpace(line.IPAddr)
	if host == "" {
		host = strings.TrimSpace(line.Domain)
	}
	if host == "" || line.DetectPort == nil || *line.DetectPort <= 0 || *line.DetectPort > 65535 || strings.ContainsAny(host, " /\\@\x00") {
		return ""
	}
	return net.JoinHostPort(host, strconv.Itoa(*line.DetectPort))
}

type connectResponse struct {
	BoostSession string         `json:"boostSession"`
	Config       *tunnelConfig  `json:"config"`
	Configs      []tunnelConfig `json:"configs"`
	LineID       int64          `json:"lineID"`
	LineName     string         `json:"lineName"`
	ProtoName    string         `json:"protoName"`
}

type tunnelConfig struct {
	Proto   *int      `json:"proto"`
	Host    string    `json:"host"`
	ProxyIP string    `json:"proxyIP"`
	InJSON  string    `json:"inJson"`
	SS      *ssConfig `json:"SSConf"`
}

type ssConfig struct {
	Server   string `json:"server"`
	Port     int    `json:"port"`
	Method   string `json:"method"`
	Password string `json:"password"`
}

type trojanRemoteConfig struct {
	RemoteAddr string   `json:"remote_addr"`
	RemotePort int      `json:"remote_port"`
	Passwords  []string `json:"password"`
	SSL        struct {
		SNI    string `json:"sni"`
		Verify *bool  `json:"verify"`
	} `json:"ssl"`
	WebSocket struct {
		Enabled bool   `json:"enabled"`
		Host    string `json:"host"`
		Path    string `json:"path"`
	} `json:"websocket"`
}

func (response connectResponse) configurations() ([]tunnelConfig, error) {
	if response.Config != nil && len(response.Configs) != 0 || len(response.Configs) > maxCatalogLines {
		return nil, ErrSchema
	}
	if response.Config != nil {
		return []tunnelConfig{*response.Config}, nil
	}
	if len(response.Configs) == 0 {
		return nil, ErrSchema
	}
	return response.Configs, nil
}

// parseTunnelConfig validates only the provider-issued tunnel. Catalog identity
// is independent: probe addresses and rotating tunnel endpoints are not routes.
func parseTunnelConfig(config tunnelConfig) (liveConfig, error) {
	if config.Proto == nil {
		return liveConfig{}, ErrSchema
	}
	var result liveConfig
	var port int
	switch *config.Proto {
	case 0:
		if config.SS == nil {
			return liveConfig{}, ErrSchema
		}
		result.Protocol, result.Host, port = ShadowsocksProtocol, config.SS.Server, config.SS.Port
		result.SS = shadowsocksEntry{Method: config.SS.Method, Password: config.SS.Password}
		if !result.SS.valid() {
			return liveConfig{}, ErrSchema
		}
	case 5:
		var remote trojanRemoteConfig
		if len(config.InJSON) == 0 || len(config.InJSON) > maxControlBytes || json.Unmarshal([]byte(config.InJSON), &remote) != nil || len(remote.Passwords) == 0 || len(remote.Passwords) > 16 || remote.SSL.Verify == nil {
			return liveConfig{}, ErrSchema
		}
		result.Protocol, result.Host, port = TrojanProtocol, remote.RemoteAddr, remote.RemotePort
		result.Trojan = trojanEntry{Password: remote.Passwords[0], SNI: remote.SSL.SNI, Verify: *remote.SSL.Verify}
		if remote.WebSocket.Enabled {
			path := remote.WebSocket.Path
			if path == "" {
				path = "/"
			}
			if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\r\n") || strings.ContainsAny(remote.WebSocket.Host, "\r\n") {
				return liveConfig{}, ErrSchema
			}
			result.Trojan.WebSocket = &trojanWebSocket{Host: remote.WebSocket.Host, Path: path}
		}
		if !result.Trojan.valid() || strings.ContainsAny(result.Trojan.SNI, "\r\n\x00") {
			return liveConfig{}, ErrSchema
		}
	default:
		return liveConfig{}, nil
	}
	if !validControlField(result.Host) || port <= 0 || port > 65535 {
		return liveConfig{}, ErrSchema
	}
	route, err := provider.Canonicalize(provider.Route{Provider: ProviderID, Protocol: result.Protocol, Host: result.Host, Port: uint16(port)})
	if err != nil {
		return liveConfig{}, fmt.Errorf("%w: tunnel endpoint", ErrSchema)
	}
	result.Host, result.Port = route.Host, route.Port
	return result, nil
}

func (line line) node(protocol provider.Protocol) (provider.Node, error) {
	authorityID := shadowsocksAuthorityID
	if protocol == TrojanProtocol {
		authorityID = trojanAuthorityID
	}
	// Catalog domain/IP/detectPort are optional probe endpoints, not guaranteed
	// unique line identities. The positive catalog ID is the stable line pin.
	route := provider.Route{Provider: ProviderID, Protocol: protocol, Host: "line-" + strconv.FormatInt(line.ID, 10) + ".transocks.invalid", Port: 1}
	id, err := provider.NodeID(route)
	if err != nil {
		return provider.Node{}, ErrSchema
	}
	return provider.Node{ID: id, AuthorityID: authorityID, Protocol: protocol, Host: route.Host, Port: route.Port, Name: line.Name, Group: line.group(), Eligible: true}, nil
}
