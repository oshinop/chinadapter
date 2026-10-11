// kfadapter is the container-only local multi-provider SOCKS adapter runtime.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
	_ "time/tzdata"

	"github.com/kfadapter/kfadapter/internal/app"
	"github.com/kfadapter/kfadapter/internal/config"
	"github.com/kfadapter/kfadapter/internal/kuaifan"
	"github.com/kfadapter/kfadapter/internal/lifecycle"
	"github.com/kfadapter/kfadapter/internal/provider"
	providercoordinator "github.com/kfadapter/kfadapter/internal/provider/coordinator"
	"github.com/kfadapter/kfadapter/internal/quickfox"
	"github.com/kfadapter/kfadapter/internal/selector"
	"github.com/kfadapter/kfadapter/internal/socks"
	"github.com/kfadapter/kfadapter/internal/state"
	"github.com/kfadapter/kfadapter/internal/subscription"
	"github.com/kfadapter/kfadapter/internal/web"
)

const (
	configPath     = "./config.yaml"
	stateDirectory = "./data"
)

// version is overwritten by Docker's -ldflags at build time.
var version = "devel"

var requireContainer = lifecycle.RequireContainer

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(arguments []string, stdout, stderr io.Writer) int {
	slog.SetDefault(slog.New(slog.NewTextHandler(stderr, nil)))
	if len(arguments) == 0 || arguments[0] == "serve" || strings.HasPrefix(arguments[0], "-") {
		if err := serve(commandArgs(arguments)); err != nil {
			// Startup and supervisor errors are operator-facing and carry no
			// provider text; refresh failures are logged by class only.
			slog.Error("service stopped", "err", err)
			fmt.Fprintln(stderr, "kfadapter: service stopped")
			return 1
		}
		return 0
	}
	switch arguments[0] {
	case "healthcheck":
		if err := healthcheck(arguments[1:]); err != nil {
			fmt.Fprintln(stderr, "kfadapter: healthcheck failed")
			return 1
		}
		return 0
	case "version":
		fmt.Fprintln(stdout, version)
		return 0
	case "validate-config":
		if err := validateConfig(arguments[1:]); err != nil {
			slog.Error("invalid configuration", "err", err)
			fmt.Fprintln(stderr, "kfadapter: invalid configuration")
			return 1
		}
		fmt.Fprintln(stdout, "configuration valid")
		return 0
	case "validate-state":
		if err := validateState(arguments[1:]); err != nil {
			fmt.Fprintln(stderr, "kfadapter: invalid state")
			return 1
		}
		fmt.Fprintln(stdout, "state valid")
		return 0
	default:
		fmt.Fprintln(stderr, "kfadapter: unknown command")
		return 2
	}
}

func commandArgs(arguments []string) []string {
	if len(arguments) > 0 && arguments[0] == "serve" {
		return arguments[1:]
	}
	return arguments
}

func loadConfig(arguments []string) (config.Config, error) {
	if len(arguments) != 0 {
		return config.Config{}, errors.New("configuration arguments are not supported")
	}
	return config.Load(configPath)
}

func validateConfig(arguments []string) error {
	_, err := loadConfig(arguments)
	return err
}

// validateState delegates secure file, integrity, schema, and aggregate
// validation to the SQLite state store without creating or modifying a file.
func validateState(arguments []string) error {
	flags := flag.NewFlagSet("validate-state", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("file", "", "")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || strings.TrimSpace(*path) == "" {
		return errors.New("invalid validate-state arguments")
	}
	return state.ValidateSQLiteFile(*path, subscription.ValidatePersistentState)
}

func healthcheck(arguments []string) error {
	cfg, err := loadConfig(arguments)
	if err != nil {
		return err
	}
	managementURL := "http://" + cfg.ManagementAddress() + "/healthz"
	proxyAddress := cfg.ProxyAddress()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, managementURL, nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errors.New("management endpoint not live")
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", proxyAddress)
	if err != nil {
		return err
	}
	return connection.Close()
}

func serve(arguments []string) error {
	cfg, err := loadConfig(arguments)
	if err != nil {
		return err
	}
	if err := requireContainer(); err != nil {
		return err
	}
	adapter, err := newAdapter(cfg)
	if err != nil {
		return err
	}
	return adapter.run()
}

type adapter struct {
	runtime            *app.Runtime
	manager            *state.Manager
	store              *state.SQLiteStore
	httpServer         *http.Server
	httpListener       net.Listener
	socksServer        *socks.Server
	socksListener      net.Listener
	startupLog         io.Writer
	managementEndpoint string
	proxyEndpoint      string
}

func newAdapter(cfg config.Config) (*adapter, error) {
	return newAdapterAtStateDirectory(cfg, stateDirectory)
}

func newAdapterAtStateDirectory(cfg config.Config, stateDirectory string) (result *adapter, err error) {
	if err := validateListenInterface(cfg.ListenAddr); err != nil {
		return nil, err
	}
	store, err := state.NewSQLiteStore(stateDirectory)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = store.Close()
		}
	}()
	persistent, err := store.LoadOrCreate(subscription.ValidatePersistentState)
	if err != nil {
		return nil, err
	}
	if persistent.ActiveSession != nil && !state.SessionUsable(persistent.ActiveSession, time.Now().UTC()) {
		persistent, err = store.Update(func(candidate *state.PersistentState) error {
			candidate.ActiveSession = nil
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	var bindingKey []byte
	if persistent.AccessTokenInitialized() {
		if persistent.AccessTokenVerifier == nil {
			return nil, errors.New("access verifier missing")
		}
		bindingKey = persistent.AccessTokenVerifier.BindingKey()
	}
	manager, err := state.NewManagerWithSubscription(persistent.ActiveSession, persistent.Subscription, bindingKey)
	if err != nil {
		return nil, err
	}
	registry, err := selector.NewRegistry(persistent.Subscription)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: cfg.Proxy.DialTimeout.Value()}
	location, err := configuredLocation()
	if err != nil {
		return nil, err
	}
	kuaifanConfig := kuaifan.Config{Location: location, RequestTimeout: cfg.Provider.RequestTimeout.Value()}
	iosClient, err := kuaifan.NewIOSClient(kuaifanConfig)
	if err != nil {
		return nil, err
	}
	windowsClient, err := kuaifan.NewWindowsClient(kuaifanConfig)
	if err != nil {
		return nil, err
	}
	kuaifanDriver, err := kuaifan.NewDriver(kuaifan.DriverConfig{
		IOSClient: iosClient, WindowsClient: windowsClient, AuthorityLifetime: 24 * time.Hour, MaxAttempts: 3,
	})
	if err != nil {
		return nil, err
	}
	quickfoxClient, err := quickfox.NewClient(quickfox.Config{Location: location, RequestTimeout: cfg.Provider.RequestTimeout.Value()})
	if err != nil {
		return nil, err
	}
	quickfoxDriver, err := quickfox.NewDriver(quickfox.DriverConfig{Client: quickfoxClient, AuthorityLifetime: 24 * time.Hour})
	if err != nil {
		return nil, err
	}
	providers, err := provider.NewRegistry(
		[]provider.Driver{kuaifanDriver, quickfoxDriver},
		[]provider.Transport{kuaifan.NewTransport(), quickfox.NewTransport()},
	)
	if err != nil {
		return nil, err
	}
	mutationMu := &sync.Mutex{}
	socksServer, err := socks.New(socks.Config{
		Snapshots: manager, Selectors: registry, Providers: providers, DialContext: dialer.DialContext,
		HandshakeTimeout: cfg.Proxy.HandshakeTimeout.Value(),
	})
	if err != nil {
		return nil, err
	}
	selectorCoordinator, err := app.NewSelectorCoordinator(socksServer, registry, time.Now)
	if err != nil {
		return nil, err
	}
	proxyAddress := cfg.ProxyAddress()
	managementAddress := cfg.ManagementAddress()
	subscriptionService, err := subscription.NewService(subscription.ServiceConfig{
		Store: store, SocksAddress: proxyAddress, Now: time.Now, MutationLocker: mutationMu,
	})
	if err != nil {
		return nil, err
	}
	var runtimeFacade *app.Runtime
	providerCoordinator, err := providercoordinator.New(providercoordinator.Config{
		Providers: providers, Manager: manager, SelectorBuilder: selectorCoordinator,
		CommitSnapshot: func(snapshot *state.RuntimeSnapshot) error {
			if runtimeFacade == nil {
				return errors.New("runtime snapshot committer unavailable")
			}
			return runtimeFacade.CommitControlSnapshotLocked(snapshot)
		},
	})
	if err != nil {
		return nil, err
	}
	startedAt := time.Now().UTC()
	runtimeFacade, err = app.NewRuntime(app.RuntimeConfig{
		Manager: manager, Store: store, Providers: providerCoordinator, Subscriptions: subscriptionService,
		Selectors: selectorCoordinator, MutationMu: mutationMu, SocksAddress: proxyAddress, HTTPAddress: managementAddress,
		Version: version, StartedAt: startedAt,
		RefreshEvery: cfg.Provider.RefreshInterval.Value(), ProbeTimeout: cfg.Proxy.DialTimeout.Value(),
	})
	if err != nil {
		return nil, err
	}
	server, api, err := web.NewHTTPServer(web.Config{
		Listen: managementAddress, Hostname: cfg.Hostname, SocksListen: proxyAddress,
		Version: version, StartedAt: startedAt, SessionTTL: cfg.Management.SessionTTL.Value(),
	}, web.Dependencies{Backend: runtimeFacade, Subscriptions: web.NewSubscriptionAdapter(subscriptionService), Sessions: store, Liveness: runtimeFacade})
	if err != nil {
		return nil, err
	}
	httpListener, err := api.Listen()
	if err != nil {
		return nil, err
	}
	socksListener, err := net.Listen("tcp", proxyAddress)
	if err != nil {
		_ = httpListener.Close()
		return nil, err
	}
	return &adapter{runtime: runtimeFacade, manager: manager, store: store, httpServer: server, httpListener: httpListener, socksServer: socksServer, socksListener: socksListener, startupLog: os.Stdout, managementEndpoint: "http://" + managementAddress, proxyEndpoint: "socks5://" + proxyAddress}, nil
}

func validateListenInterface(listen string) error {
	addresses, err := localInterfaceAddresses()
	if err != nil {
		return err
	}
	return validateListenInterfaceAddresses(listen, addresses)
}

func localInterfaceAddresses() ([]netip.Addr, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("inspect network interfaces: %w", err)
	}
	var result []netip.Addr
	for _, networkInterface := range interfaces {
		if networkInterface.Flags&net.FlagUp == 0 {
			continue
		}
		addresses, err := networkInterface.Addrs()
		if err != nil {
			return nil, fmt.Errorf("inspect network interface %q: %w", networkInterface.Name, err)
		}
		for _, address := range addresses {
			raw := address.String()
			if slash := strings.LastIndexByte(raw, '/'); slash >= 0 {
				raw = raw[:slash]
			}
			ip, err := netip.ParseAddr(raw)
			if err == nil {
				result = append(result, ip.WithZone("").Unmap())
			}
		}
	}
	return result, nil
}

func validateListenInterfaceAddresses(listen string, addresses []netip.Addr) error {
	listenIP, err := netip.ParseAddr(listen)
	if err != nil {
		return fmt.Errorf("invalid listen address %q", listen)
	}
	listenIP = listenIP.Unmap()
	for _, address := range addresses {
		address = address.Unmap()
		if address.Is4() == listenIP.Is4() && (listenIP.IsUnspecified() || address == listenIP) {
			return nil
		}
	}
	if listenIP.IsUnspecified() {
		return fmt.Errorf("listen address %s has no reachable up local network interface of the same address family", listen)
	}
	return fmt.Errorf("listen address %s is not assigned to a reachable up local network interface", listen)
}

func configuredLocation() (*time.Location, error) {
	zone := os.Getenv("TZ")
	if zone == "" {
		zone = "Asia/Shanghai"
	}
	return time.LoadLocation(zone)
}

// adapterDrainTimeout leaves a ten-second margin before Compose's 30-second
// stop grace period so internal cleanup completes before Docker SIGKILL.
var adapterDrainTimeout = 20 * time.Second

func newAdapterSupervisor(workers []lifecycle.Worker) (*lifecycle.Supervisor, error) {
	return lifecycle.New(workers, adapterDrainTimeout)
}

func (d *adapter) run() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	return d.runContext(ctx)
}

func (d *adapter) runContext(ctx context.Context) (result error) {
	defer func() {
		if err := d.store.Close(); err != nil && result == nil {
			result = err
		}
	}()
	supervisor, err := newAdapterSupervisor([]lifecycle.Worker{
		{Name: "proxy", Run: d.runSOCKS, Shutdown: d.shutdownSOCKS},
		{Name: "management", Run: d.runWeb, Shutdown: d.shutdownWeb},
		{Name: "heartbeat", Run: d.runHeartbeat, Shutdown: func(context.Context) error { d.runtime.Stop(); return nil }},
		{Name: "watchdog", Run: lifecycle.Watchdog(10*time.Second, 3, d.watchdog)},
	})
	if err != nil {
		return err
	}
	if d.startupLog != nil {
		_, _ = fmt.Fprintf(d.startupLog, "kfadapter: ready management=%s proxy=%s\n", d.managementEndpoint, d.proxyEndpoint)
	}
	return supervisor.Run(ctx)
}

func (d *adapter) runSOCKS(ctx context.Context) error {
	err := d.socksServer.Serve(ctx, d.socksListener)
	if err == nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func (d *adapter) shutdownSOCKS(ctx context.Context) error {
	return d.socksServer.Shutdown(ctx)
}

func (d *adapter) runWeb(ctx context.Context) error {
	err := d.httpServer.Serve(d.httpListener)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func (d *adapter) shutdownWeb(ctx context.Context) error {
	return d.httpServer.Shutdown(ctx)
}

func (d *adapter) runHeartbeat(ctx context.Context) error {
	expiryTicker := time.NewTicker(time.Minute)
	defer expiryTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case now := <-expiryTicker.C:
			// Refresh failures are normal degraded-control-plane events; they
			// must not stop an otherwise healthy local adapter. Only the error
			// class is logged so provider text never reaches the log.
			if err := d.runtime.Heartbeat(ctx, d.runtime.RefreshDue(now)); err != nil {
				slog.Warn("provider refresh failed", "class", refreshErrorClass(err))
			}
		}
	}
}

func (d *adapter) watchdog(context.Context) error {
	if !d.runtime.Healthy() {
		return errors.New("runtime is stopped")
	}
	_, err := d.store.Load()
	return err
}

// refreshErrorClass names a refresh failure category without rendering the
// underlying provider error, which may echo control-plane text.
func refreshErrorClass(err error) string {
	switch {
	case errors.Is(err, provider.ErrLoginRejected):
		return "login_rejected"
	case errors.Is(err, provider.ErrNoSession):
		return "no_session"
	default:
		return "unclassified"
	}
}
