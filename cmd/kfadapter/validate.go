package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"strings"

	"github.com/kfadapter/kfadapter/internal/config"
	"github.com/kfadapter/kfadapter/internal/store"
)

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
	return store.ValidateSQLiteFile(context.Background(), *path)
}
