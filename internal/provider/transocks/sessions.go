package transocks

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/oshinop/chinadapter/internal/provider"
)

var ErrProtocolMismatch = errors.New("transocks: tunnel protocol differs from node; refresh the catalog")

type liveConfig struct {
	Protocol   provider.Protocol
	Host       string
	Port       uint16
	SS         shadowsocksEntry
	Trojan     trojanEntry
	generation uint64
}

type sessionKey struct {
	account [32]byte
	lineID  int64
}

type cachedSession struct {
	config liveConfig
	used   uint64
}

type pendingSession struct {
	done   chan struct{}
	config liveConfig
	err    error
}

// SessionManager shares a two-line LRU across both protocols. Eviction forgets
// the config; there is no disconnect call. Control-plane connects are serialized
// so cache insertion order agrees with the account's two most recent connects.
// It does not keep tunnels alive or substitute another line on any failure.
type SessionManager struct {
	client    *Client
	connectMu sync.Mutex
	mu        sync.Mutex
	clock     uint64
	cache     map[sessionKey]cachedSession
	pending   map[sessionKey]*pendingSession
	observed  map[sessionKey]provider.Protocol
}

func NewSessionManager(client *Client) *SessionManager {
	return &SessionManager{client: client, cache: make(map[sessionKey]cachedSession, 2), pending: make(map[sessionKey]*pendingSession), observed: make(map[sessionKey]provider.Protocol)}
}

// NewTransports shares the client's manager with protocol discovery in Driver.
func NewTransports(client *Client) (*ShadowsocksTransport, *TrojanTransport) {
	var sessions *SessionManager
	if client != nil {
		sessions = client.sessions
	}
	return NewShadowsocksTransport(sessions), NewTrojanTransport(sessions)
}

func keyFor(session storedSession, lineID int64) sessionKey {
	session.Protocols = nil
	data, _ := json.Marshal(session)
	return sessionKey{account: sha256.Sum256(data), lineID: lineID}
}

func (manager *SessionManager) protocol(session storedSession, lineID int64) (provider.Protocol, bool) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	protocol, found := manager.observed[keyFor(session, lineID)]
	return protocol, found
}

func (client *Client) connectConfig(ctx context.Context, session storedSession, lineID int64) (liveConfig, error) {
	response, err := client.Connect(ctx, session, lineID)
	if err != nil {
		return liveConfig{}, err
	}
	if response.LineID != 0 && response.LineID != lineID {
		return liveConfig{}, fmt.Errorf("%w: connect returned another line", ErrSchema)
	}
	configs, err := response.configurations()
	if err != nil {
		return liveConfig{}, err
	}
	// A physical line must resolve unambiguously to one tunnel. Never select a
	// second endpoint/config from an auto-line or multi-line response.
	if len(configs) != 1 {
		return liveConfig{}, fmt.Errorf("%w: ambiguous physical line config", ErrSchema)
	}
	return parseTunnelConfig(configs[0])
}

// stale is non-nil only for the single retry of a refused/reset cached config.
// A concurrent reconnect that has already replaced it is reused, not repeated.
func (manager *SessionManager) resolve(ctx context.Context, session storedSession, lineID int64, stale *liveConfig) (liveConfig, bool, error) {
	if manager == nil || manager.client == nil {
		return liveConfig{}, false, ErrInvalidAuthority
	}
	key := keyFor(session, lineID)
	manager.mu.Lock()
	if cached, ok := manager.cache[key]; ok {
		if stale == nil || cached.config.generation != stale.generation {
			manager.clock++
			cached.used = manager.clock
			manager.cache[key] = cached
			manager.mu.Unlock()
			return cached.config, true, nil
		}
		delete(manager.cache, key)
	}
	if pending, ok := manager.pending[key]; ok {
		manager.mu.Unlock()
		select {
		case <-pending.done:
			return pending.config, false, pending.err
		case <-ctx.Done():
			return liveConfig{}, false, ctx.Err()
		}
	}
	pending := &pendingSession{done: make(chan struct{})}
	manager.pending[key] = pending
	manager.mu.Unlock()

	manager.connectMu.Lock()
	var config liveConfig
	err := ctx.Err()
	if err == nil {
		config, err = manager.client.connectConfig(ctx, session, lineID)
	}
	manager.mu.Lock()
	if err == nil {
		manager.observed[key] = config.Protocol
		manager.clock++
		config.generation = manager.clock
		if config.Protocol != "" {
			if len(manager.cache) == 2 {
				var oldest sessionKey
				used := ^uint64(0)
				for candidate, cached := range manager.cache {
					if cached.used < used {
						oldest, used = candidate, cached.used
					}
				}
				delete(manager.cache, oldest)
			}
			manager.cache[key] = cachedSession{config: config, used: manager.clock}
		}
	}
	pending.config, pending.err = config, err
	delete(manager.pending, key)
	close(pending.done)
	manager.mu.Unlock()
	manager.connectMu.Unlock()
	return config, false, err
}

func (manager *SessionManager) open(ctx context.Context, data []byte, host string, port uint16, protocol provider.Protocol, open func(liveConfig) (net.Conn, error)) (net.Conn, liveConfig, error) {
	session, lineID, err := authorityFor(data, host, port)
	if err != nil {
		return nil, liveConfig{}, err
	}
	config, cached, err := manager.resolve(ctx, session, lineID, nil)
	if err != nil {
		return nil, liveConfig{}, err
	}
	if config.Protocol != protocol {
		return nil, liveConfig{}, ErrProtocolMismatch
	}
	connection, err := open(config)
	if err == nil || !cached || (!errors.Is(err, syscall.ECONNREFUSED) && !errors.Is(err, syscall.ECONNRESET)) {
		return connection, config, err
	}
	config, _, err = manager.resolve(ctx, session, lineID, &config)
	if err != nil {
		return nil, liveConfig{}, err
	}
	if config.Protocol != protocol {
		return nil, liveConfig{}, ErrProtocolMismatch
	}
	connection, err = open(config)
	return connection, config, err
}

func (manager *SessionManager) dialShadowsocks(ctx context.Context, data []byte, host string, port uint16, dial provider.DialContextFunc, network string, timeout time.Duration) (net.Conn, liveConfig, error) {
	return manager.open(ctx, data, host, port, ShadowsocksProtocol, func(config liveConfig) (net.Conn, error) {
		return dialTransocks(ctx, dial, network, config.Host, config.Port, timeout)
	})
}
