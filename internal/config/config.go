package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Zeek      ZeekConfig      `yaml:"zeek"`
	BZAR      BZARConfig      `yaml:"bzar"`
	Evidence  EvidenceConfig  `yaml:"evidence"`
	OCSF      OCSFConfig      `yaml:"ocsf"`
	Forwarder ForwarderConfig `yaml:"forwarder"`
	Logging   LoggingConfig   `yaml:"logging"`
}

type ZeekConfig struct {
	LogDir    string   `yaml:"log_dir"`
	LogFormat string   `yaml:"log_format"` // tsv or json
	Logs      []string `yaml:"logs"`
}

type BZARConfig struct {
	Enabled bool `yaml:"enabled"`
}

type EvidenceConfig struct {
	Enabled       bool   `yaml:"enabled"`
	OutputDir     string `yaml:"output_dir"`
	RetentionDays int    `yaml:"retention_days"`
	MaxSizeMB     int    `yaml:"max_size_mb"`
	BufferSize    int    `yaml:"buffer_size"` // max entries per uid in memory
}

type OCSFConfig struct {
	Version  string       `yaml:"version"`
	Producer OCSFProducer `yaml:"producer"`
}

type OCSFProducer struct {
	Name    string `yaml:"name"`
	Version string `yaml:"version"`
	URL     string `yaml:"url"`
}

type ForwarderConfig struct {
	Outputs []OutputConfig `yaml:"outputs"`
}

type OutputConfig struct {
	Type string `yaml:"type"` // file, syslog, http

	// file output
	Path string `yaml:"path"`

	// syslog output
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Protocol string `yaml:"protocol"` // udp or tcp

	// http output
	URL      string            `yaml:"url"`
	Headers  map[string]string `yaml:"headers"`
	Timeout  int               `yaml:"timeout_seconds"`
	Insecure bool              `yaml:"insecure"`

	// shared
	BatchSize  int `yaml:"batch_size"`
	MaxRetries int `yaml:"max_retries"`
}

type LoggingConfig struct {
	Level  string `yaml:"level"`  // debug, info, warn, error
	Output string `yaml:"output"` // stdout, stderr, or file path
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}
	return cfg, nil
}

func DefaultConfig() *Config {
	return &Config{
		Zeek: ZeekConfig{
			LogDir:    "/opt/zeek/logs/current",
			LogFormat: "tsv",
			Logs:      []string{"conn", "dns", "http", "ssl", "smb_files", "smb_mapping", "dce_rpc", "notice"},
		},
		BZAR: BZARConfig{
			Enabled: true,
		},
		Evidence: EvidenceConfig{
			Enabled:       true,
			OutputDir:     "/var/lib/zeek-bzar-ocsf/evidence",
			RetentionDays: 30,
			MaxSizeMB:     1024,
			BufferSize:    500,
		},
		OCSF: OCSFConfig{
			Version: "1.1.0",
			Producer: OCSFProducer{
				Name:    "zeek-bzar-ocsf",
				Version: "1.0.0",
				URL:     "https://github.com/zeekurity/zeek-bzar-ocsf",
			},
		},
		Forwarder: ForwarderConfig{
			Outputs: []OutputConfig{
				{
					Type: "file",
					Path: "/var/log/zeek-bzar-ocsf/events.json",
				},
			},
		},
		Logging: LoggingConfig{
			Level:  "info",
			Output: "stdout",
		},
	}
}
