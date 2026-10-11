package socks

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/kfadapter/kfadapter/internal/provider"
	"github.com/kfadapter/kfadapter/internal/selector"
	"github.com/kfadapter/kfadapter/internal/state"
)

const (
	defaultHandshakeTimeout = 10 * time.Second
	defaultMaxConnections   = 1024
	maximumMaxConnections   = 65536
)

// SnapshotSource resolves compact tunnel pins without exposing a runtime
// snapshot or selector map to the SOCKS hot path. state.Manager is the
// production implementation.
type SnapshotSource interface {
	CompactPin(selector string, now time.Time) (state.TunnelPin, error)
	SessionCurrentPin(pin state.TunnelPin, now time.Time) bool
}

// Config defines the SOCKS listener's dependency boundaries.
type Config struct {
	Snapshots SnapshotSource
	Selectors *selector.Registry
	Providers *provider.Registry

	DialContext      provider.DialContextFunc
	HandshakeTimeout time.Duration
	MaxConnections   int
}

// Server is a SOCKS5/RFC1929 frontend. Its selector registry is atomically
// replaceable for subscription rotation; every established session retains
// only a compact state tunnel pin, never a runtime snapshot.
type Server struct {
	snapshots        SnapshotSource
	providers        *provider.Registry
	dial             provider.DialContextFunc
	handshakeTimeout time.Duration
	slots            chan struct{}
	selectors        atomic.Pointer[selector.Registry]

	lifecycleMu  sync.Mutex
	listener     net.Listener
	shuttingDown bool
	active       map[net.Conn]context.CancelFunc
	drained      chan struct{}
}

// New constructs a server. Listener selection belongs to the caller.
func New(config Config) (*Server, error) {
	if config.Snapshots == nil {
		return nil, errors.New("socks: snapshot source is required")
	}
	if config.Selectors == nil {
		return nil, errors.New("socks: selector registry is required")
	}
	if config.Providers == nil {
		return nil, errors.New("socks: provider registry is required")
	}
	timeout := config.HandshakeTimeout
	if timeout == 0 {
		timeout = defaultHandshakeTimeout
	}
	if timeout < 0 {
		return nil, errors.New("socks: handshake timeout must be positive")
	}
	maxConnections := config.MaxConnections
	if maxConnections == 0 {
		maxConnections = defaultMaxConnections
	}
	if maxConnections < 1 || maxConnections > maximumMaxConnections {
		return nil, fmt.Errorf("socks: max connections must be in 1..%d", maximumMaxConnections)
	}
	dial := config.DialContext
	if dial == nil {
		dialer := &net.Dialer{}
		dial = dialer.DialContext
	}
	drained := make(chan struct{})
	close(drained)
	server := &Server{snapshots: config.Snapshots, providers: config.Providers, dial: dial, handshakeTimeout: timeout, slots: make(chan struct{}, maxConnections), active: make(map[net.Conn]context.CancelFunc), drained: drained}
	server.selectors.Store(config.Selectors)
	return server, nil
}

// SetSelectors atomically adopts an immutable registry containing the current
// subscription authority. Existing TCP flows are unaffected.
func (s *Server) SetSelectors(registry *selector.Registry) error {
	if s == nil || registry == nil {
		return errors.New("socks: selector registry is required")
	}
	s.selectors.Store(registry)
	return nil
}

// Shutdown stops accepting new SOCKS connections and waits for active
// handlers to drain. When ctx expires, it cancels and closes every remaining
// handler so relays and in-flight setup cannot outlive the shutdown deadline.
func (s *Server) Shutdown(ctx context.Context) error {
	if s == nil || ctx == nil {
		return errors.New("socks: server and shutdown context are required")
	}
	s.lifecycleMu.Lock()
	s.shuttingDown = true
	listener := s.listener
	s.listener = nil
	drained := s.drained
	s.lifecycleMu.Unlock()
	if listener != nil {
		_ = listener.Close()
	}
	select {
	case <-drained:
		return nil
	case <-ctx.Done():
		s.forceActiveHandlers()
		return ctx.Err()
	}
}

func (s *Server) beginServe(listener net.Listener) error {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	if s.shuttingDown {
		return errors.New("socks: server is shutting down")
	}
	if s.listener != nil {
		return errors.New("socks: server is already serving")
	}
	s.listener = listener
	return nil
}

func (s *Server) endServe(listener net.Listener) {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	if s.listener == listener {
		s.listener = nil
	}
}

func (s *Server) accepting(listener net.Listener) bool {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	return !s.shuttingDown && s.listener == listener
}

func (s *Server) addActiveHandler(connection net.Conn, cancel context.CancelFunc) bool {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	if s.shuttingDown {
		return false
	}
	if len(s.active) == 0 {
		s.drained = make(chan struct{})
	}
	s.active[connection] = cancel
	return true
}

func (s *Server) removeActiveHandler(connection net.Conn) {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	delete(s.active, connection)
	if len(s.active) == 0 {
		close(s.drained)
	}
}

func (s *Server) forceActiveHandlers() {
	s.lifecycleMu.Lock()
	handlers := make([]struct {
		connection net.Conn
		cancel     context.CancelFunc
	}, 0, len(s.active))
	for connection, cancel := range s.active {
		handlers = append(handlers, struct {
			connection net.Conn
			cancel     context.CancelFunc
		}{connection: connection, cancel: cancel})
	}
	s.lifecycleMu.Unlock()
	for _, handler := range handlers {
		handler.cancel()
		_ = handler.connection.Close()
	}
}

// Serve accepts connections until ctx is canceled. Accepted handlers retain
// independent contexts and must be drained with Shutdown.
func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	if s == nil || ctx == nil || listener == nil {
		return errors.New("socks: server, context, and listener are required")
	}
	if err := s.beginServe(listener); err != nil {
		return err
	}
	defer s.endServe(listener)
	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
		case <-stop:
		}
	}()
	defer close(stop)

	var retryDelay time.Duration
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || !s.accepting(listener) {
				return nil
			}
			if !temporaryAcceptError(err) {
				return err
			}
			retryDelay = nextAcceptRetry(retryDelay)
			timer := time.NewTimer(retryDelay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil
			case <-timer.C:
			}
			continue
		}
		retryDelay = 0
		select {
		case s.slots <- struct{}{}:
			handlerCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
			if !s.addActiveHandler(connection, cancel) {
				cancel()
				_ = connection.Close()
				<-s.slots
				continue
			}
			go func(connection net.Conn, handlerCtx context.Context, cancel context.CancelFunc) {
				defer func() { <-s.slots }()
				defer s.removeActiveHandler(connection)
				defer cancel()
				_ = s.HandleConn(handlerCtx, connection)
			}(connection, handlerCtx, cancel)
		default:
			_ = connection.Close()
		}
	}
}

// temporaryAcceptError reports accept failures caused by transient resource
// pressure, such as descriptor exhaustion, rather than a closed listener.
func temporaryAcceptError(err error) bool {
	if errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE) ||
		errors.Is(err, syscall.ECONNABORTED) || errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EINTR) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// nextAcceptRetry doubles the accept backoff from 5ms, capped at one second.
func nextAcceptRetry(previous time.Duration) time.Duration {
	switch {
	case previous == 0:
		return 5 * time.Millisecond
	case previous >= time.Second/2:
		return time.Second
	default:
		return previous * 2
	}
}

// HandleConn processes one SOCKS connection. It never logs credentials,
// tunnel material, provider extensions, or requested destinations.
func (s *Server) HandleConn(ctx context.Context, client net.Conn) error {
	if s == nil || client == nil {
		return errors.New("socks: server and client are required")
	}
	defer client.Close()
	handlerDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = client.Close()
		case <-handlerDone:
		}
	}()
	defer close(handlerDone)
	if err := client.SetDeadline(time.Now().Add(s.handshakeTimeout)); err != nil {
		return fmt.Errorf("socks: set client setup deadline: %w", err)
	}
	if err := negotiate(client, client); err != nil {
		return err
	}
	username, password, err := readUserPassword(client)
	if err != nil {
		_ = writeAuthStatus(client, false)
		return err
	}

	// Authenticate credentials first, then retain only a compact state-owned
	// tunnel pin. No runtime snapshot or selector map escapes into this flow.
	now := time.Now()
	registry := s.selectors.Load()
	if registry == nil {
		_ = writeAuthStatus(client, false)
		return state.ErrSelectorUnknown
	}
	authenticated := registry.AuthenticateAt(username, password, now)
	if !authenticated {
		_ = writeAuthStatus(client, false)
		return state.ErrSelectorUnknown
	}
	pin, err := s.snapshots.CompactPin(username, now)
	node := pin.Node
	if err != nil || !node.TunnelEligible() {
		_ = writeAuthStatus(client, false)
		if err != nil {
			return err
		}
		return state.ErrSelectorUnknown
	}
	if err := writeAuthStatus(client, true); err != nil {
		return err
	}

	command, destination, err := readRequest(client)
	if err != nil {
		code := replyGeneralFailure
		if errors.Is(err, errAddressTypeUnsupported) {
			code = replyAddressUnsupported
		}
		_ = writeReply(client, code, target{})
		return err
	}
	if command != commandConnect && command != commandUDP {
		_ = writeReply(client, replyCommandUnsupported, target{})
		return nil
	}
	if command == commandConnect && destination.Port == 0 {
		_ = writeReply(client, replyGeneralFailure, target{})
		return errBadAddress
	}
	// Authentication may have completed before a client supplies CONNECT. Do
	// not let a stalled socket create a tunnel after logout, authority
	// refresh, selector rotation, preference exclusion, or node replacement.
	// Re-resolving returns a compact current pin and never clones a snapshot.
	now = time.Now()
	registry = s.selectors.Load()
	if registry == nil {
		_ = writeReply(client, replyGeneralFailure, target{})
		return state.ErrSelectorUnknown
	}
	authenticated = registry.AuthenticateAt(username, password, now)
	if !authenticated {
		_ = writeReply(client, replyGeneralFailure, target{})
		return state.ErrSelectorUnknown
	}
	revalidatedPin, resolveErr := s.snapshots.CompactPin(username, now)
	revalidatedNode := revalidatedPin.Node
	if resolveErr != nil || s.selectors.Load() != registry || !samePinAuthority(pin, revalidatedPin) || !revalidatedNode.TunnelEligible() || !sameCanonicalNode(node, revalidatedNode) {
		_ = writeReply(client, replyGeneralFailure, target{})
		if resolveErr != nil {
			return resolveErr
		}
		return state.ErrSelectorUnknown
	}
	pin, node = revalidatedPin, revalidatedNode
	if err := client.SetDeadline(time.Time{}); err != nil {
		_ = writeReply(client, replyGeneralFailure, target{})
		return fmt.Errorf("socks: clear client setup deadline: %w", err)
	}

	transport, err := s.providers.Transport(node.Protocol)
	if err != nil {
		_ = writeReply(client, replyGeneralFailure, target{})
		return err
	}
	var association *udpAssociation
	if command == commandUDP {
		association, err = newUDPAssociation(client, destination)
		if err != nil {
			code := replyGeneralFailure
			if errors.Is(err, errAddressTypeUnsupported) {
				code = replyAddressUnsupported
			}
			_ = writeReply(client, code, target{})
			return err
		}
		defer func() { _ = association.Close() }()
	}
	admit := func() bool {
		now := time.Now()
		if !s.snapshots.SessionCurrentPin(pin, now) {
			return false
		}
		currentRegistry := s.selectors.Load()
		if currentRegistry == nil {
			return false
		}
		authenticated := currentRegistry.AuthenticateAt(username, password, now)
		if !authenticated {
			return false
		}
		finalPin, resolveErr := s.snapshots.CompactPin(username, now)
		finalNode := finalPin.Node
		if resolveErr != nil || s.selectors.Load() != currentRegistry || !samePinAuthority(pin, finalPin) || !finalNode.TunnelEligible() || !sameCanonicalNode(node, finalNode) {
			return false
		}
		pin, node = finalPin, finalNode
		return true
	}
	ready := false
	readyRelay := func(bound net.Addr) error {
		if err := writeReply(client, replySucceeded, targetFromAddr(bound)); err != nil {
			return err
		}
		ready = true
		return nil
	}
	if association != nil {
		err = transport.RelayDatagrams(ctx, provider.DatagramRequest{
			Dial: s.dial, Control: client, Packets: association, NodeHost: node.Host, NodePort: node.Port,
			Authority: pin.Authority.Data, HandshakeTimeout: s.handshakeTimeout, Admit: admit, Ready: readyRelay,
		})
	} else {
		err = transport.RelayStream(ctx, provider.RelayRequest{
			Dial: s.dial, Client: client, NodeHost: node.Host, NodePort: node.Port,
			Target: provider.Target{Host: destination.Host, Port: destination.Port}, Authority: pin.Authority.Data,
			HandshakeTimeout: s.handshakeTimeout, Admit: admit, Ready: readyRelay,
		})
	}
	if err != nil && !ready {
		_ = writeReply(client, dialReply(err), target{})
	}
	return err
}

func samePinAuthority(left, right state.TunnelPin) bool {
	return left.Authority.Protocol == right.Authority.Protocol &&
		subtle.ConstantTimeCompare(left.Authority.Data, right.Authority.Data) == 1
}

func sameCanonicalNode(left, right state.Node) bool {
	leftIdentity, leftErr := selector.Canonicalize(selector.NodeIdentity{NodeID: left.ID, Provider: string(left.Provider), Host: left.Host, Port: int(left.Port)})
	rightIdentity, rightErr := selector.Canonicalize(selector.NodeIdentity{NodeID: right.ID, Provider: string(right.Provider), Host: right.Host, Port: int(right.Port)})
	return leftErr == nil && rightErr == nil && leftIdentity == rightIdentity
}

func targetFromAddr(address net.Addr) target {
	switch value := address.(type) {
	case *net.TCPAddr:
		if value != nil && value.Port > 0 && value.Port <= 65535 {
			return target{Host: value.IP.String(), Port: uint16(value.Port)}
		}
	case *net.UDPAddr:
		if value != nil && value.Port > 0 && value.Port <= 65535 {
			return target{Host: value.IP.String(), Port: uint16(value.Port)}
		}
	}
	return target{}
}

func dialReply(err error) byte {
	if errors.Is(err, context.DeadlineExceeded) {
		return replyTTLExpired
	}
	var networkErr net.Error
	if errors.As(err, &networkErr) && networkErr.Timeout() {
		return replyTTLExpired
	}
	if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
		return replyConnectionForbidden
	}
	if errors.Is(err, syscall.ENETUNREACH) {
		return replyNetworkUnreachable
	}
	if errors.Is(err, syscall.EHOSTUNREACH) {
		return replyHostUnreachable
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return replyConnectionRefused
	}
	return replyGeneralFailure
}
