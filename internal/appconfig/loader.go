package appconfig

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/VojtechPastyrik/muthur/internal/notify"
	"github.com/VojtechPastyrik/muthur/internal/routing"
)

// FileConfig is the top-level structure of the muthur config file,
// typically mounted at /config/muthur.yaml from a ConfigMap.
type FileConfig struct {
	Receivers []notify.ReceiverConfig `yaml:"receivers"`
	Routing   routing.Config          `yaml:"routing"`
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
