package routing

import (
	pb "github.com/VojtechPastyrik/muthur/proto"
)

type Rule struct {
	Name      string   `yaml:"name" json:"name"`
	Match     Match    `yaml:"match" json:"match"`
	Receivers []string `yaml:"receivers" json:"receivers"`
}

type Match struct {
	Severity  string `yaml:"severity,omitempty" json:"severity,omitempty"`
	ClusterID string `yaml:"cluster_id,omitempty" json:"cluster_id,omitempty"`
	AlertName string `yaml:"alert_name,omitempty" json:"alert_name,omitempty"`
	Namespace string `yaml:"namespace,omitempty" json:"namespace,omitempty"`
}

func (r *Rule) Matches(payload *pb.AlertPayload) bool {
	if r.Match.Severity != "" && r.Match.Severity != payload.Severity {
		return false
	}
	if r.Match.ClusterID != "" && r.Match.ClusterID != payload.ClusterId {
		return false
	}
	if r.Match.AlertName != "" && r.Match.AlertName != payload.AlertName {
		return false
	}
	if r.Match.Namespace != "" && r.Match.Namespace != payload.Namespace {
		return false
	}
	return true
}
