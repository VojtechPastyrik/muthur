package routing

import (
	"go.uber.org/zap"

	pb "github.com/VojtechPastyrik/muthur/proto"
)

type Config struct {
	Rules []Rule `yaml:"rules"`
}

type Router struct {
	rules  []Rule
	logger *zap.Logger
}

// New constructs a Router from a pre-parsed list of rules.
func New(rules []Rule, logger *zap.Logger) *Router {
	logger.Info("loaded routing rules", zap.Int("count", len(rules)))
	for _, r := range rules {
		logger.Info("routing rule",
			zap.String("name", r.Name),
			zap.Strings("receivers", r.Receivers),
		)
	}
	return &Router{rules: rules, logger: logger}
}

// Route returns the list of receiver names that should handle the given alert.
// First matching rule wins. Returns nil if no rule matches.
func (r *Router) Route(payload *pb.AlertPayload) []string {
	for _, rule := range r.rules {
		if rule.Matches(payload) {
			r.logger.Info("matched routing rule",
				zap.String("rule", rule.Name),
				zap.String("alert", payload.AlertName),
				zap.Strings("receivers", rule.Receivers),
			)
			return rule.Receivers
		}
	}

	r.logger.Warn("no routing rule matched",
		zap.String("alert", payload.AlertName),
		zap.String("severity", payload.Severity),
		zap.String("cluster_id", payload.ClusterId),
	)
	return nil
}
