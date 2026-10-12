package main

import (
	"errors"

	"github.com/kfadapter/kfadapter/internal/config"
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
