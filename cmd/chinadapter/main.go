// chinadapter is the container-only local multi-provider SOCKS adapter runtime.
package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/oshinop/chinadapter/internal/app"
	"github.com/oshinop/chinadapter/internal/lifecycle"
)

const (
	configPath     = "./config.yaml"
	stateDirectory = "./data"
)
const usageLine = "usage: chinadapter [serve|healthcheck|version|validate-config]"

// version is overwritten by Docker's -ldflags at build time.
var version = "devel"

var requireContainer = lifecycle.RequireContainer

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(arguments []string, stdout, stderr io.Writer) int {
	slog.SetDefault(slog.New(slog.NewTextHandler(stderr, nil)))
	if len(arguments) == 0 {
		if err := serve(nil); err != nil {
			slog.Error("service stopped", "err", err)
			fmt.Fprintln(stderr, "chinadapter: service stopped")
			return 1
		}
		return 0
	}
	if arguments[0] == "serve" {
		if len(arguments) != 1 {
			fmt.Fprintln(stderr, usageLine)
			return 2
		}
		if err := serve(nil); err != nil {
			slog.Error("service stopped", "err", err)
			fmt.Fprintln(stderr, "chinadapter: service stopped")
			return 1
		}
		return 0
	}
	if strings.HasPrefix(arguments[0], "-") {
		fmt.Fprintln(stderr, usageLine)
		return 2
	}
	switch arguments[0] {
	case "healthcheck":
		if err := healthcheck(arguments[1:]); err != nil {
			fmt.Fprintln(stderr, "chinadapter: healthcheck failed")
			return 1
		}
		return 0
	case "version":
		fmt.Fprintln(stdout, version)
		return 0
	case "validate-config":
		if err := validateConfig(arguments[1:]); err != nil {
			slog.Error("invalid configuration", "err", err)
			fmt.Fprintln(stderr, "chinadapter: invalid configuration")
			return 1
		}
		fmt.Fprintln(stdout, "configuration valid")
		return 0
	default:
		fmt.Fprintln(stderr, usageLine)
		return 2
	}
}

func serve(arguments []string) error {
	cfg, err := loadConfig(arguments)
	if err != nil {
		return err
	}
	if err := requireContainer(); err != nil {
		return err
	}
	adapter, err := app.NewDaemon(cfg, stateDirectory, version)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	return adapter.Run(ctx)
}
