package subscription

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"unicode/utf8"

	"github.com/kfadapter/kfadapter/internal/credentials"
	"github.com/kfadapter/kfadapter/internal/provider"
	"github.com/kfadapter/kfadapter/internal/state"
	"github.com/kfadapter/kfadapter/internal/store"
)

const (
	subscriptionResponseConcurrency = 8
	subscriptionResponseChunkBytes  = 32 << 10
	maxMetadataFilterBytes          = 512
)

type ServiceConfig struct {
	Store        *store.SQLiteStore
	SocksAddress string
}

// Service publishes an immutable credential authority and node catalog. No
// subscription request loads or writes SQLite, mutates shared state, or takes
// the control-plane mutation lock.
type Service struct {
	socksAddress  string
	current       atomic.Pointer[catalog]
	responseSlots chan struct{}
}
type catalog struct {
	identity *credentials.Identity
	nodes    []state.Node
}

func NewService(config ServiceConfig) (*Service, error) {
	if config.Store == nil {
		return nil, errors.New("subscription: state store is required")
	}
	if err := validateAddress(config.SocksAddress); err != nil {
		return nil, err
	}
	persistent, err := config.Store.Load(context.Background())
	if err != nil {
		return nil, err
	}
	service := &Service{socksAddress: config.SocksAddress, responseSlots: make(chan struct{}, subscriptionResponseConcurrency)}
	if err := service.Update(persistent); err != nil {
		return nil, err
	}
	return service, nil
}

// Update swaps a catalog only after its corresponding durable control commit.
func (service *Service) Update(persistent state.PersistentState) error {
	authority, err := persistent.Identity()
	if err != nil {
		return err
	}
	next := &catalog{identity: authority}
	if persistent.ActiveSession != nil {
		for _, node := range persistent.ActiveSession.Nodes {
			if _, available := persistent.ActiveSession.Providers[node.Provider]; !available {
				continue
			}
			node.Excluded = persistent.Preferences.ExcludedNodeIDs[node.ID]
			next.nodes = append(next.nodes, node)
		}
	}
	service.current.Store(next)
	return nil
}

func (service *Service) Metadata() (Metadata, error) {
	if service == nil {
		return Metadata{}, ErrSubscriptionUnavailable
	}
	current := service.current.Load()
	if current == nil || current.identity.SubscriptionID() == "" {
		return Metadata{}, nil
	}
	count := 0
	for _, node := range current.nodes {
		if node.TunnelEligible() && !node.Excluded {
			count++
		}
	}
	return Metadata{Active: count > 0, NodeCount: count}, nil
}

func (service *Service) SubscriptionURL(baseURL string) (string, error) {
	if service == nil {
		return "", ErrSubscriptionUnavailable
	}
	current := service.current.Load()
	if current == nil || current.identity.SubscriptionID() == "" {
		return "", ErrSubscriptionUnavailable
	}
	return subscriptionURL(baseURL, current.identity.SubscriptionID()), nil
}

// HandleSubscription owns path validation so response saturation is checked
// first, uniformly for valid and invalid paths. The advertised SOCKS authority
// is request-local, never written back into the catalog.
func (service *Service) HandleSubscription(w http.ResponseWriter, r *http.Request, socksAddress string) {
	select {
	case service.responseSlots <- struct{}{}:
		defer func() { <-service.responseSlots }()
	default:
		writeResponseBusy(w)
		return
	}
	id, valid := credentials.ParseSubscriptionPath(r.URL.EscapedPath())
	filter, validFilter := parseSubscriptionFilter(r.URL.RawQuery)
	if r.Method != http.MethodGet || !valid || !validFilter {
		writeNotFound(w)
		return
	}
	current := service.current.Load()
	if current == nil || !current.identity.MatchesSubscriptionID(id) {
		writeNotFound(w)
		return
	}
	if socksAddress == "" {
		socksAddress = service.socksAddress
	}
	body, _, err := Render(current.nodes, filter, socksAddress, current.identity)
	if errors.Is(err, ErrNoEligibleLinks) {
		writeNotFound(w)
		return
	}
	if err != nil {
		writeResponseUnavailable(w)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	_, _ = writeSubscriptionBody(w, body)
}

func writeResponseBusy(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "1")
	writeResponseUnavailable(w)
}
func writeResponseUnavailable(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Length", "0")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusServiceUnavailable)
}

func parseSubscriptionFilter(rawQuery string) (Filter, bool) {
	if rawQuery == "" {
		return Filter{}, true
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return Filter{}, false
	}
	for key := range values {
		if key != "provider" && key != "group" && key != "name" {
			return Filter{}, false
		}
	}
	providerValue, ok := singleFilterValue(values, "provider", 32)
	if !ok {
		return Filter{}, false
	}
	group, ok := singleFilterValue(values, "group", maxMetadataFilterBytes)
	if !ok {
		return Filter{}, false
	}
	name, ok := singleFilterValue(values, "name", maxMetadataFilterBytes)
	if !ok {
		return Filter{}, false
	}
	filter := Filter{Provider: provider.ID(providerValue), Group: group, Name: name}
	if providerValue != "" && !filter.Provider.Valid() {
		return Filter{}, false
	}
	return filter, true
}
func singleFilterValue(values url.Values, key string, maxBytes int) (string, bool) {
	items, exists := values[key]
	if !exists {
		return "", true
	}
	if len(items) != 1 || items[0] == "" || len(items[0]) > maxBytes || !utf8.ValidString(items[0]) || strings.IndexByte(items[0], 0) >= 0 || strings.TrimSpace(items[0]) != items[0] {
		return "", false
	}
	return items[0], true
}
func writeSubscriptionBody(w io.Writer, body string) (int, error) {
	written := 0
	for len(body) != 0 {
		limit := min(len(body), subscriptionResponseChunkBytes)
		n, err := io.WriteString(w, body[:limit])
		written += n
		if err != nil {
			return written, err
		}
		if n != limit {
			return written, io.ErrShortWrite
		}
		body = body[n:]
	}
	return written, nil
}
