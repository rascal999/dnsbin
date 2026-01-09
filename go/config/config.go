package config

import (
	"encoding/json"
	"os"
)

type Config struct {
	Resolver    string `json:"resolver"`
	Domain      string `json:"domain"`
	Debug       bool   `json:"debug"`
	MaxLen      int    `json:"maxlen"`
	Options     byte   `json:"options"`
	Concurrency int    `json:"concurrency"`
}

const ConfigPath = "config.json"

func Load() Config {
	var config Config
	file, err := os.Open(ConfigPath)
	if err != nil {
		return Config{Resolver: "192.168.1.1:53", Domain: "web.app", Debug: false, MaxLen: 65535, Options: 0x04, Concurrency: 16}
	}
	defer file.Close()
	json.NewDecoder(file).Decode(&config)
	if config.Concurrency == 0 {
		config.Concurrency = 16
	}
	if config.MaxLen == 0 {
		config.MaxLen = 1024
	}
	return config
}

func Save(config Config) error {
	file, err := os.Create(ConfigPath)
	if err != nil {
		return err
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(config)
}