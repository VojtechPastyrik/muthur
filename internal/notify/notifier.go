package notify

import (
	"context"

	pb "github.com/VojtechPastyrik/muthur-central/proto"
	"github.com/VojtechPastyrik/muthur-central/internal/evaluator"
)

type Notifier interface {
	Name() string
	Send(ctx context.Context, msg *Message) error
}

type Message struct {
	Text       string
	Severity   string
	ClusterID  string
	AlertName  string
	Namespace  string
	PodName    string
	GrafanaURL string
	Payload    *pb.AlertPayload
	Analysis   *evaluator.Analysis
}
