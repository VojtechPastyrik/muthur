package appconfig

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/VojtechPastyrik/muthur/internal/auth"
	"github.com/VojtechPastyrik/muthur/internal/notify"
	"github.com/VojtechPastyrik/muthur/internal/routing"
)

// FileConfig is the top-level structure of the muthur config file,
// typically mounted at /config/muthur.yaml from a ConfigMap.
type FileConfig struct {
	Receivers []notify.ReceiverConfig `yaml:"receivers"`
	Routing   routing.Config          `yaml:"routing"`

	// Tenants enumerates the collectors authorised to bootstrap. Each entry
	// carries the SHA-256 of a one-time bootstrap token (vendor-issued at
	// onboarding) plus the lifetime cert-manager should target for that
	// tenant's leaves.
	Tenants []auth.Tenant `yaml:"tenants"`
}

// Load reads and parses the config file at the given path.
func Load(path string) (*FileConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file %s: %w", path, err)
	}

	var fc FileConfig
	if err := yaml.Unmarshal(data, &fc); err != nil {
		return nil, fmt.Errorf("parse config file %s: %w", path, err)
	}

	return &fc, nil
}
