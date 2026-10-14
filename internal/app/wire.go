package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"
	_ "time/tzdata"

	"github.com/oshinop/chinadapter/internal/accounts"
	"github.com/oshinop/chinadapter/internal/config"
	"github.com/oshinop/chinadapter/internal/lifecycle"
	"github.com/oshinop/chinadapter/internal/provider"
	"github.com/oshinop/chinadapter/internal/provider/baidu"
	"github.com/oshinop/chinadapter/internal/provider/kuaifan"
	"github.com/oshinop/chinadapter/internal/provider/quickfox"
	"github.com/oshinop/chinadapter/internal/provider/transocks"
	"github.com/oshinop/chinadapter/internal/socks"
	"github.com/oshinop/chinadapter/internal/state"
	"github.com/oshinop/chinadapter/internal/store"
	"github.com/oshinop/chinadapter/internal/subscription"
	"github.com/oshinop/chinadapter/internal/web"
)

// Daemon owns the wired services, listeners, and process lifecycle workers.
type Daemon struct {
	runtime            *Runtime
	manager            *state.Manager
	store              *store.SQLiteStore
	httpServer         *http.Server
	httpListener       net.Listener
	socksServer        *socks.Server
	socksListener      net.Listener
	startupLog         io.Writer
	managementEndpoint string
	proxyEndpoint      string
}

// NewDaemon constructs the stateful services and opens the daemon listeners.
func NewDaemon(cfg config.Config, stateDirectory, version string) (result *Daemon, err error) {
	if err := validateListenInterface(cfg.ListenAddr); err != nil {
		return nil, err
	}
	store, err := store.NewSQLiteStore(stateDirectory)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = store.Close(context.Background())
		}
	}()
	persistent, err := store.LoadOrCreate(context.Background())
	if err != nil {
		return nil, err
	}
	authority, err := persistent.Identity()
	if err != nil {
		return nil, err
	}
	manager, err := state.NewManager(persistent.ActiveSession)
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
	transocksClient, err := transocks.NewClient(transocks.Config{RequestTimeout: cfg.Provider.RequestTimeout.Value()})
	if err != nil {
		return nil, err
	}
	transocksDriver, err := transocks.NewDriver(transocks.DriverConfig{Client: transocksClient})
	if err != nil {
		return nil, err
	}
	transocksSS, transocksTrojan := transocks.NewTransports(transocksClient)
	providers, err := provider.NewRegistry(
		[]provider.Driver{kuaifanDriver, quickfoxDriver, transocksDriver, baidu.NewDriver(baidu.DriverConfig{})},
		[]provider.Transport{
			kuaifan.NewTransport(), kuaifan.NewSPEEDINTransport(), quickfox.NewTransport(),
			transocksSS, transocksTrojan, baidu.NewTransport(),
		},
	)
	if err != nil {
		return nil, err
	}
	mutationMu := &sync.Mutex{}
	socksServer, err := socks.New(socks.Config{
		Snapshots: manager, Identity: authority, InitialSnapshot: persistent.ActiveSession, Providers: providers, DialContext: dialer.DialContext,
		HandshakeTimeout: cfg.Proxy.HandshakeTimeout.Value(),
	})
	if err != nil {
		return nil, err
	}
	credentialCoordinator, err := NewCredentialCoordinator(socksServer, authority)
	if err != nil {
		return nil, err
	}
	proxyAddress := cfg.ProxyAddress()
	managementAddress := cfg.ManagementAddress()
	subscriptionService, err := subscription.NewService(subscription.ServiceConfig{
		Store: store, SocksAddress: proxyAddress,
	})
	if err != nil {
		return nil, err
	}
	var runtimeFacade *Runtime
	providerCoordinator, err := accounts.NewCoordinator(accounts.CoordinatorConfig{
		Providers: providers, Manager: manager, SelectorBuilder: credentialCoordinator,
		MutationMu: mutationMu,
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
	runtimeFacade, err = NewRuntime(RuntimeConfig{
		Manager: manager, Store: store, Providers: providerCoordinator, Subscriptions: subscriptionService,
		Credentials: credentialCoordinator, MutationMu: mutationMu, SocksAddress: proxyAddress, HTTPAddress: managementAddress,
		Version: version, StartedAt: startedAt,
		RefreshEvery: cfg.Provider.RefreshInterval.Value(), ProbeTimeout: cfg.Proxy.DialTimeout.Value(), Transports: providers,
		AccountRefresh: func(_ provider.ID, err error) {
			if err != nil {
				// Provider text may contain secrets; emit only its classification.
				slog.Warn("provider refresh failed", "class", accounts.ErrorClass(err))
			}
		},
	})
	if err != nil {
		return nil, err
	}
	server, api, err := web.NewHTTPServer(web.Config{
		Listen: managementAddress, Hostname: cfg.Hostname, SocksListen: proxyAddress,
		Version: version, StartedAt: startedAt, SessionTTL: cfg.Management.SessionTTL.Value(),
		ProviderRequestTimeout: cfg.Provider.RequestTimeout.Value(),
	}, web.Dependencies{Backend: runtimeFacade, Subscriptions: NewSubscriptionAdapter(subscriptionService), Sessions: store, Liveness: runtimeFacade})
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
	return &Daemon{runtime: runtimeFacade, manager: manager, store: store, httpServer: server, httpListener: httpListener, socksServer: socksServer, socksListener: socksListener, startupLog: os.Stdout, managementEndpoint: "http://" + managementAddress, proxyEndpoint: "socks5://" + proxyAddress}, nil
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

// Run supervises the daemon workers until cancellation or component failure.
func (d *Daemon) Run(ctx context.Context) (result error) {
	defer func() {
		if err := d.store.Close(ctx); err != nil && result == nil {
			result = err
		}
	}()
	supervisor, err := newAdapterSupervisor([]lifecycle.Worker{
		{Name: "proxy", Run: d.runSOCKS, Shutdown: d.shutdownSOCKS},
		{Name: "management", Run: d.runWeb, Shutdown: d.shutdownWeb},
		{Name: "accounts", Run: d.runtime.RunAccounts, Shutdown: func(context.Context) error { d.runtime.Stop(); return nil }},
		{Name: "watchdog", Run: lifecycle.Watchdog(10*time.Second, 3, d.watchdog)},
	})
	if err != nil {
		return err
	}
	if d.startupLog != nil {
		_, _ = fmt.Fprintf(d.startupLog, "chinadapter: ready management=%s proxy=%s\n", d.managementEndpoint, d.proxyEndpoint)
	}
	return supervisor.Run(ctx)
}

func (d *Daemon) runSOCKS(ctx context.Context) error {
	err := d.socksServer.Serve(ctx, d.socksListener)
	if err == nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func (d *Daemon) shutdownSOCKS(ctx context.Context) error {
	return d.socksServer.Shutdown(ctx)
}

func (d *Daemon) runWeb(ctx context.Context) error {
	d.httpServer.BaseContext = func(net.Listener) context.Context { return ctx }
	err := d.httpServer.Serve(d.httpListener)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func (d *Daemon) shutdownWeb(ctx context.Context) error {
	return d.httpServer.Shutdown(ctx)
}

func (d *Daemon) watchdog(ctx context.Context) error {
	if !d.runtime.Healthy() {
		return errors.New("runtime is stopped")
	}
	_, err := d.store.Load(ctx)
	return err
}
