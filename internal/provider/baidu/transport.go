package baidu

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/oshinop/chinadapter/internal/provider"
)

const (
	maxAuthorityBytes   = 4096
	maxResponseHeader   = 16 << 10
	relayBufferSize     = 32 << 10
	unlimitedReadBudget = 1<<63 - 1
)

var (
	// ErrInvalidAuthority identifies malformed opaque proxy authority.
	ErrInvalidAuthority = errors.New("baidu: invalid proxy authority")
	// ErrConnectRefused reports a non-200 CONNECT response, for example 403
	// when Baidu stops accepting the shared proxy token.
	ErrConnectRefused = errors.New("baidu: proxy refused CONNECT")
)

// proxyAuthority is the opaque authority data: the headers the proxy requires.
type proxyAuthority struct {
	Host      string `json:"host"`
	Token     string `json:"token"`
	UserAgent string `json:"userAgent"`
}

func validHeaderValue(value string) bool {
	return value != "" && len(value) <= 512 && !strings.ContainsAny(value, "\r\n\x00")
}

func (authority proxyAuthority) valid() bool {
	return validHeaderValue(authority.Host) && validHeaderValue(authority.Token) && validHeaderValue(authority.UserAgent)
}

func encodeAuthority(authority proxyAuthority) (provider.Authority, error) {
	if !authority.valid() {
		return provider.Authority{}, ErrInvalidAuthority
	}
	data, err := json.Marshal(authority)
	if err != nil {
		return provider.Authority{}, ErrInvalidAuthority
	}
	return provider.Authority{Protocol: Protocol, Data: data}, nil
}

func decodeAuthority(data []byte) (proxyAuthority, error) {
	var authority proxyAuthority
	if len(data) == 0 || len(data) > maxAuthorityBytes || json.Unmarshal(data, &authority) != nil || !authority.valid() {
		return proxyAuthority{}, ErrInvalidAuthority
	}
	return authority, nil
}

// Transport tunnels SOCKS CONNECT through the proxy with HTTP CONNECT. It is
// TCP-only: HTTP CONNECT cannot carry UDP, so UDP ASSOCIATE receives 0x07.
type Transport struct{}

func NewTransport() *Transport { return &Transport{} }

var _ provider.Transport = (*Transport)(nil)

func (*Transport) Protocol() provider.Protocol { return Protocol }

func (*Transport) RelayStream(ctx context.Context, request provider.RelayRequest) error {
	if ctx == nil || request.Dial == nil || request.Client == nil || request.NodeHost == "" || request.NodePort == 0 ||
		request.Target.Host == "" || request.Target.Port == 0 || request.Admit == nil || request.Ready == nil || request.HandshakeTimeout <= 0 {
		return errors.New("baidu: invalid stream relay request")
	}
	authority, err := decodeAuthority(request.Authority)
	if err != nil {
		return err
	}
	target, err := connectTarget(request.Target)
	if err != nil {
		return err
	}
	dialCtx, cancel := context.WithTimeout(ctx, request.HandshakeTimeout)
	upstream, err := request.Dial(dialCtx, "tcp", net.JoinHostPort(request.NodeHost, strconv.Itoa(int(request.NodePort))))
	cancel()
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("baidu: connect proxy: %w", err)
	}
	defer upstream.Close()
	tunnel, err := handshake(upstream, authority, target, request.HandshakeTimeout)
	if err != nil {
		return err
	}
	if !request.Admit() {
		return provider.ErrNoSession
	}
	if err := request.Ready(upstream.LocalAddr()); err != nil {
		return err
	}
	return relay(ctx, request.Client, tunnel)
}

// connectTarget formats the CONNECT authority. The proxy answers IPv6 targets
// with 503, so they are reported as unsupported before dialing.
func connectTarget(target provider.Target) (string, error) {
	if address, err := netip.ParseAddr(target.Host); err == nil && !address.Unmap().Is4() {
		return "", fmt.Errorf("baidu: IPv6 targets are unsupported: %w", provider.ErrAddressUnsupported)
	}
	if strings.ContainsAny(target.Host, " \r\n\x00/@") {
		return "", fmt.Errorf("baidu: invalid target host: %w", provider.ErrAddressUnsupported)
	}
	return net.JoinHostPort(target.Host, strconv.Itoa(int(target.Port))), nil
}

// handshake sends CONNECT and requires a 200. It returns a connection whose
// reads first drain any bytes the proxy sent after its response headers.
func handshake(upstream net.Conn, authority proxyAuthority, target string, timeout time.Duration) (net.Conn, error) {
	if err := upstream.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("baidu: set handshake deadline: %w", err)
	}
	request := "CONNECT " + target + " HTTP/1.1\r\nHost: " + authority.Host + "\r\nX-T5-Auth: " + authority.Token +
		"\r\nUser-Agent: " + authority.UserAgent + "\r\nProxy-Connection: keep-alive\r\n\r\n"
	if _, err := io.WriteString(upstream, request); err != nil {
		return nil, fmt.Errorf("baidu: write CONNECT: %w", err)
	}
	limited := &io.LimitedReader{R: upstream, N: maxResponseHeader}
	reader := bufio.NewReader(limited)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return nil, fmt.Errorf("baidu: read CONNECT response: %w", err)
	}
	// A 2xx CONNECT response has no body; an error body is discarded with the
	// connection.
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: HTTP %d", ErrConnectRefused, response.StatusCode)
	}
	limited.N = unlimitedReadBudget
	if err := upstream.SetDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("baidu: clear handshake deadline: %w", err)
	}
	return &bufferedConn{Conn: upstream, reader: reader}, nil
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (connection *bufferedConn) Read(buffer []byte) (int, error) {
	return connection.reader.Read(buffer)
}

func (connection *bufferedConn) CloseWrite() error {
	if closer, ok := connection.Conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return connection.Close()
}

// relay copies both directions, propagating half-close, until both finish or
// the context is cancelled.
func relay(ctx context.Context, client, upstream net.Conn) error {
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			_ = client.Close()
			_ = upstream.Close()
		})
	}
	stop := context.AfterFunc(ctx, closeBoth)
	defer stop()
	results := make(chan error, 2)
	pump := func(destination, source net.Conn) {
		_, err := io.CopyBuffer(destination, source, make([]byte, relayBufferSize))
		if err == nil {
			if closer, ok := destination.(interface{ CloseWrite() error }); ok {
				err = closer.CloseWrite()
			} else {
				err = destination.Close()
			}
		}
		if err != nil && !benign(err) {
			closeBoth()
		}
		results <- err
	}
	go pump(upstream, client)
	go pump(client, upstream)
	first, second := <-results, <-results
	closeBoth()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	for _, err := range []error{first, second} {
		if err != nil && !benign(err) {
			return err
		}
	}
	return nil
}

func benign(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe)
}
