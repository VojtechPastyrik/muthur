package routing

import (
	"fmt"
	"os"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"

	pb "github.com/VojtechPastyrik/muthur-central/proto"
)

type RoutingConfig struct {
	Rules []Rule `yaml:"rules"`
}

type Router struct {
	rules  []Rule
	logger *zap.Logger
}

func NewRouter(configPath string, logger *zap.Logger) (*Router, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read routing config: %w", err)
	}

	var cfg RoutingConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse routing config: %w", err)
	}

	logger.Info("loaded routing rules", zap.Int("count", len(cfg.Rules)))
	for _, r := range cfg.Rules {
		logger.Info("routing rule",
			zap.String("name", r.Name),
			zap.Strings("notify", r.Notify),
		)
	}

	return &Router{rules: cfg.Rules, logger: logger}, nil
}

func (r *Router) Route(payload *pb.AlertPayload) []string {
	for _, rule := range r.rules {
		if rule.Matches(payload) {
			r.logger.Info("matched routing rule",
				zap.String("rule", rule.Name),
				zap.String("alert", payload.AlertName),
				zap.Strings("notify", rule.Notify),
			)
			return rule.Notify
		}
	}

	r.logger.Warn("no routing rule matched",
		zap.String("alert", payload.AlertName),
		zap.String("severity", payload.Severity),
		zap.String("cluster_id", payload.ClusterId),
	)
	return nil
}
