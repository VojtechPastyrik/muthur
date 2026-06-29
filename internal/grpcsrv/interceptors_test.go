package grpcsrv

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/VojtechPastyrik/muthur/internal/auth"
	pb "github.com/VojtechPastyrik/muthur/proto"
)

func newTestTenants(t *testing.T, revoked bool) *auth.Tenants {
	t.Helper()
	tenants, err := auth.NewTenants([]auth.Tenant{
		{
			ClusterID:          "c1",
			TenantID:           "v1",
			BootstrapTokenHash: "deadbeef",
			BootstrapExpiresAt: time.Now().Add(time.Hour),
			Revoked:            revoked,
			CertDurationStr:    "24h",
		},
	})
	if err != nil {
		t.Fatalf("NewTenants: %v", err)
	}
	return tenants
}

func okHandler(_ context.Context, _ any) (any, error) { return "ok", nil }

func TestRevocationInterceptor_RejectsRevoked(t *testing.T) {
	tenants := newTestTenants(t, true)
	ctx := auth.WithContext(context.Background(), &auth.Identity{ClusterID: "c1", SerialNumber: "abc"})

	_, err := RevocationInterceptor(auth.StaticTenants{T: tenants}, zap.NewNop())(
		ctx, nil, &grpc.UnaryServerInfo{FullMethod: pb.Brain_Ingest_FullMethodName}, okHandler,
	)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}
}

func TestRevocationInterceptor_RejectsUnknownTenant(t *testing.T) {
	tenants := newTestTenants(t, false)
	ctx := auth.WithContext(context.Background(), &auth.Identity{ClusterID: "ghost", SerialNumber: "abc"})

	_, err := RevocationInterceptor(auth.StaticTenants{T: tenants}, zap.NewNop())(
		ctx, nil, &grpc.UnaryServerInfo{FullMethod: pb.Brain_Ingest_FullMethodName}, okHandler,
	)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}
}

func TestRevocationInterceptor_AllowsActiveTenant(t *testing.T) {
	tenants := newTestTenants(t, false)
	ctx := auth.WithContext(context.Background(), &auth.Identity{ClusterID: "c1", SerialNumber: "abc"})

	got, err := RevocationInterceptor(auth.StaticTenants{T: tenants}, zap.NewNop())(
		ctx, nil, &grpc.UnaryServerInfo{FullMethod: pb.Brain_Ingest_FullMethodName}, okHandler,
	)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got != "ok" {
		t.Fatalf("handler not invoked; got %v", got)
	}
}

func TestRevocationInterceptor_SkipsBootstrap(t *testing.T) {
	tenants := newTestTenants(t, true)
	got, err := RevocationInterceptor(auth.StaticTenants{T: tenants}, zap.NewNop())(
		context.Background(), nil,
		&grpc.UnaryServerInfo{FullMethod: pb.Brain_BootstrapCert_FullMethodName}, okHandler,
	)
	if err != nil {
		t.Fatalf("bootstrap must skip revocation check; got %v", err)
	}
	if got != "ok" {
		t.Fatalf("bootstrap handler not invoked; got %v", got)
	}
}

func TestRevocationInterceptor_RejectsMissingIdentity(t *testing.T) {
	tenants := newTestTenants(t, false)
	_, err := RevocationInterceptor(auth.StaticTenants{T: tenants}, zap.NewNop())(
		context.Background(), nil,
		&grpc.UnaryServerInfo{FullMethod: pb.Brain_Ingest_FullMethodName}, okHandler,
	)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("want Unauthenticated, got %v", err)
	}
}
