package notify

import (
	"fmt"
	"os"
	"strings"

	"go.uber.org/zap"
)

// ReceiverConfig is a single named receiver loaded from the config file.
// Multiple receivers of the same type can coexist (e.g., three Discord webhooks).
type ReceiverConfig struct {
	Name   string            `yaml:"name"`
	Type   string            `yaml:"type"`
	Config map[string]string `yaml:"config"`
}

// Factory builds a Notifier instance for a specific receiver type.
// The name is the receiver's unique identifier used in routing rules.
// The cfg map contains already-resolved values (file references read from disk).
type Factory func(name string, cfg map[string]string) (Notifier, error)

// factories holds the built-in notifier factories, keyed by type name.
var factories = map[string]Factory{
	"telegram":  newTelegram,
	"discord":   newDiscord,
	"slack":     newSlack,
	"pagerduty": newPagerDuty,
	"webhook":   newWebhook,
}

// BuildReceivers constructs notifier instances from the given receiver configs.
// Returns a map keyed by receiver name. Invalid or unknown receivers are logged
// and skipped rather than failing the whole startup.
func BuildReceivers(configs []ReceiverConfig, logger *zap.Logger) (map[string]Notifier, error) {
	out := make(map[string]Notifier, len(configs))
	seen := make(map[string]struct{}, len(configs))

	for _, rc := range configs {
		if rc.Name == "" {
			logger.Warn("receiver has empty name, skipping", zap.String("type", rc.Type))
			continue
		}
		if _, dup := seen[rc.Name]; dup {
			return nil, fmt.Errorf("duplicate receiver name: %q", rc.Name)
		}
		seen[rc.Name] = struct{}{}

		factory, ok := factories[rc.Type]
		if !ok {
			logger.Warn("unknown receiver type, skipping",
				zap.String("name", rc.Name),
				zap.String("type", rc.Type))
			continue
		}

		resolved, err := resolveConfig(rc.Config)
		if err != nil {
			logger.Warn("failed to resolve receiver config, skipping",
				zap.String("name", rc.Name),
				zap.String("type", rc.Type),
				zap.Error(err))
			continue
		}

		n, err := factory(rc.Name, resolved)
		if err != nil {
			logger.Warn("failed to build receiver, skipping",
				zap.String("name", rc.Name),
				zap.String("type", rc.Type),
				zap.Error(err))
			continue
		}

		out[rc.Name] = n
		logger.Info("registered receiver",
			zap.String("name", rc.Name),
			zap.String("type", rc.Type))
	}

	return out, nil
}

// resolveConfig resolves file references in a receiver config map.
//
// For any key with the suffix "_file", the value is treated as a path to a
// file (typically a mounted Kubernetes Secret). The file contents (trimmed of
// trailing whitespace) replace the value, and the key is rewritten to drop the
// "_file" suffix.
//
// Example:
//
//	input:  {"token_file": "/secrets/ops-telegram-token", "chat_id": "-100123"}
//	output: {"token":      "<file contents>",             "chat_id": "-100123"}
//
// Keys without the "_file" suffix are passed through unchanged.
func resolveConfig(cfg map[string]string) (map[string]string, error) {
	out := make(map[string]string, len(cfg))
	for k, v := range cfg {
		if strings.HasSuffix(k, "_file") {
			baseKey := strings.TrimSuffix(k, "_file")
			data, err := os.ReadFile(v)
			if err != nil {
				return nil, fmt.Errorf("read secret file for %q (path %q): %w", baseKey, v, err)
			}
			out[baseKey] = strings.TrimRight(string(data), " \t\r\n")
			continue
		}
		out[k] = v
	}
	return out, nil
}
