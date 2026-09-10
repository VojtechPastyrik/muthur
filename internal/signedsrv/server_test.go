package signedsrv_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/VojtechPastyrik/muthur/internal/auth"
	"github.com/VojtechPastyrik/muthur/internal/signedsrv"
	"github.com/VojtechPastyrik/muthur/internal/store"
	pb "github.com/VojtechPastyrik/muthur/proto"
)

// pki is a throwaway root → intermediate → collector leaf chain.
type pki struct {
	rootFile, interCertFile, interKeyFile string
	rootCert                              *x509.Certificate
	signer                                *auth.Signer
	trust                                 *auth.TrustPools
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	dir := t.TempDir()

	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTpl, rootTpl, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootDER)

	interKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	interTpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Test Intermediate"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	interDER, _ := x509.CreateCertificate(rand.Reader, interTpl, rootCert, &interKey.PublicKey, rootKey)
	interKeyDER, _ := x509.MarshalPKCS8PrivateKey(interKey)

	p := &pki{
		rootFile:      filepath.Join(dir, "root.crt"),
		interCertFile: filepath.Join(dir, "inter.crt"),
		interKeyFile:  filepath.Join(dir, "inter.key"),
		rootCert:      rootCert,
	}
	write := func(path, typ string, der []byte) {
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(p.rootFile, "CERTIFICATE", rootDER)
	write(p.interCertFile, "CERTIFICATE", interDER)
	write(p.interKeyFile, "PRIVATE KEY", interKeyDER)

	var err error
	if p.signer, err = auth.NewSignerFromFiles(p.interCertFile, p.interKeyFile); err != nil {
		t.Fatal(err)
	}
	if p.trust, err = auth.LoadTrustPools(p.rootFile, p.interCertFile); err != nil {
		t.Fatal(err)
	}
	return p
}

// leaf issues a collector cert for clusterID through the intermediate.
func (p *pki) leaf(t *testing.T, clusterID string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: clusterID}}, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	leafPEM, err := p.signer.Sign(csrPEM, auth.Identity{ClusterID: clusterID, TenantID: "tenant"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(leafPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

type fakeBrain struct {
	pb.UnimplementedBrainServer
	lastIdentity *auth.Identity
	lastPayload  *pb.AlertPayload
	bootstrapReq *pb.BootstrapRequest
	ingestErr    error
}

func (f *fakeBrain) Ingest(ctx context.Context, p *pb.AlertPayload) (*pb.IngestResponse, error) {
	f.lastIdentity, _ = auth.FromContext(ctx)
	f.lastPayload = p
	if f.ingestErr != nil {
		return nil, f.ingestErr
	}
	return &pb.IngestResponse{}, nil
}

func (f *fakeBrain) BootstrapCert(ctx context.Context, r *pb.BootstrapRequest) (*pb.BootstrapResponse, error) {
	if id, ok := auth.FromContext(ctx); ok {
		return nil, status.Error(codes.Internal, "bootstrap must not carry identity: "+id.String())
	}
	f.bootstrapReq = r
	return &pb.BootstrapResponse{Certificate: "LEAF", Ca: "CA"}, nil
}

func (f *fakeBrain) SignCSR(ctx context.Context, _ *pb.SignCSRRequest) (*pb.SignCSRResponse, error) {
	f.lastIdentity, _ = auth.FromContext(ctx)
	return &pb.SignCSRResponse{Certificate: "NEWLEAF", Ca: "CA"}, nil
}

type staticTenants struct{ t *auth.Tenants }

func (s staticTenants) Current() *auth.Tenants { return s.t }

type fixture struct {
	srv   *httptest.Server
	brain *fakeBrain
	pki   *pki
	keys  *auth.HPKEKeySet
	pub   auth.HPKEPublicKey
}

func newFixture(t *testing.T, revoked bool) *fixture {
	t.Helper()
	p := newPKI(t)
	keyPEM, _ := auth.GenerateHPKEKeyPEM()
	keys, err := auth.ParseHPKEKeys(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	tenants, err := auth.NewTenants([]auth.Tenant{{ClusterID: "cluster-a", TenantID: "tenant", Revoked: revoked}})
	if err != nil {
		t.Fatal(err)
	}
	brain := &fakeBrain{}
	h := signedsrv.New(signedsrv.Deps{
		Brain:   brain,
		Tenants: staticTenants{tenants},
		Replay:  auth.NewReplayGuard(store.NewMemory(), 5*time.Minute, "t:"),
		Keys:    keys,
		Trust:   p.trust,
		Signer:  p.signer,
		Logger:  zap.NewNop(),
	})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &fixture{srv: srv, brain: brain, pki: p, keys: keys, pub: keys.Public()[0]}
}

type call struct {
	path   string
	msg    proto.Message
	leaf   *x509.Certificate
	key    *ecdsa.PrivateKey
	mutate func(*http.Request, []byte)
}

// do performs one sealed (and, when a leaf is given, signed) request the way
// a collector would, returning the HTTP response and the decrypted body.
func (f *fixture) do(t *testing.T, c call) (*http.Response, []byte) {
	t.Helper()
	raw, err := proto.Marshal(c.msg)
	if err != nil {
		t.Fatal(err)
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := strings.Repeat("ab", 16) + strconv.FormatInt(time.Now().UnixNano(), 16)
	body, opener, err := auth.SealRequest(f.pub.Key, c.path, ts, nonce, raw)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, f.srv.URL+c.path, bytes.NewReader(body))
	req.Header.Set("Content-Type", auth.SealedContentType)
	req.Header.Set(auth.HeaderContentDigest, auth.ContentDigest(body))
	req.Header.Set(auth.HeaderTimestamp, ts)
	req.Header.Set(auth.HeaderNonce, nonce)
	req.Header.Set(auth.HeaderHPKEKid, f.pub.KID)
	if c.leaf != nil {
		req.Header.Set(auth.HeaderCert, base64.StdEncoding.EncodeToString(c.leaf.Raw))
		created, _ := strconv.ParseInt(ts, 10, 64)
		if err := auth.SignRequest(req.Header, http.MethodPost, c.path, c.key, c.leaf.Raw, created); err != nil {
			t.Fatal(err)
		}
	}
	if c.mutate != nil {
		c.mutate(req, body)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusOK {
		pt, err := opener.Open(data)
		if err != nil {
			t.Fatalf("open response: %v", err)
		}
		return resp, pt
	}
	return resp, data
}

func errCode(t *testing.T, data []byte) string {
	t.Helper()
	var e signedsrv.ErrorBody
	if err := json.Unmarshal(data, &e); err != nil {
		t.Fatalf("error body %q: %v", data, err)
	}
	return e.Error
}

func TestIngest_SignedAndSealed(t *testing.T) {
	f := newFixture(t, false)
	leaf, key := f.pki.leaf(t, "cluster-a")
	resp, pt := f.do(t, call{path: signedsrv.PathIngest, msg: &pb.AlertPayload{ClusterId: "cluster-a", AlertName: "Down"}, leaf: leaf, key: key})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, pt)
	}
	var out pb.IngestResponse
	if err := proto.Unmarshal(pt, &out); err != nil {
		t.Fatal(err)
	}
	if f.brain.lastIdentity == nil || f.brain.lastIdentity.ClusterID != "cluster-a" || f.brain.lastIdentity.TenantID != "tenant" {
		t.Fatalf("identity %+v", f.brain.lastIdentity)
	}
	if f.brain.lastPayload.GetAlertName() != "Down" {
		t.Fatalf("payload %+v", f.brain.lastPayload)
	}
}

func TestBootstrap_UnsignedButSealed(t *testing.T) {
	f := newFixture(t, false)
	resp, pt := f.do(t, call{path: signedsrv.PathBootstrap, msg: &pb.BootstrapRequest{ClusterId: "cluster-a", BootstrapToken: "tok", Csr: "csr"}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, pt)
	}
	var out pb.BootstrapResponse
	if err := proto.Unmarshal(pt, &out); err != nil {
		t.Fatal(err)
	}
	if out.GetCertificate() != "LEAF" || f.brain.bootstrapReq.GetBootstrapToken() != "tok" {
		t.Fatalf("unexpected bootstrap round trip: %+v / %+v", &out, f.brain.bootstrapReq)
	}
}

func TestSignCSR_UsesCertIdentity(t *testing.T) {
	f := newFixture(t, false)
	leaf, key := f.pki.leaf(t, "cluster-a")
	resp, _ := f.do(t, call{path: signedsrv.PathSignCSR, msg: &pb.SignCSRRequest{Csr: "csr"}, leaf: leaf, key: key})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if f.brain.lastIdentity == nil || f.brain.lastIdentity.ClusterID != "cluster-a" {
		t.Fatalf("identity %+v", f.brain.lastIdentity)
	}
}

func TestIngest_RejectsUnsigned(t *testing.T) {
	f := newFixture(t, false)
	resp, data := f.do(t, call{path: signedsrv.PathIngest, msg: &pb.AlertPayload{ClusterId: "cluster-a"}})
	if resp.StatusCode != http.StatusUnauthorized || errCode(t, data) != signedsrv.CodeBadCert {
		t.Fatalf("status %d body %s", resp.StatusCode, data)
	}
}

func TestIngest_RejectsForeignCA(t *testing.T) {
	f := newFixture(t, false)
	other := newPKI(t)
	leaf, key := other.leaf(t, "cluster-a")
	resp, data := f.do(t, call{path: signedsrv.PathIngest, msg: &pb.AlertPayload{ClusterId: "cluster-a"}, leaf: leaf, key: key})
	if resp.StatusCode != http.StatusUnauthorized || errCode(t, data) != signedsrv.CodeBadCert {
		t.Fatalf("status %d body %s", resp.StatusCode, data)
	}
}

func TestIngest_RejectsTamperedHeaders(t *testing.T) {
	f := newFixture(t, false)
	leaf, key := f.pki.leaf(t, "cluster-a")
	resp, data := f.do(t, call{path: signedsrv.PathIngest, msg: &pb.AlertPayload{ClusterId: "cluster-a"}, leaf: leaf, key: key,
		mutate: func(r *http.Request, _ []byte) { r.Header.Set(auth.HeaderNonce, strings.Repeat("cd", 20)) }})
	if resp.StatusCode != http.StatusUnauthorized || errCode(t, data) != signedsrv.CodeBadSignature {
		t.Fatalf("status %d body %s", resp.StatusCode, data)
	}
}

func TestIngest_RejectsTamperedBody(t *testing.T) {
	f := newFixture(t, false)
	leaf, key := f.pki.leaf(t, "cluster-a")
	resp, data := f.do(t, call{path: signedsrv.PathIngest, msg: &pb.AlertPayload{ClusterId: "cluster-a"}, leaf: leaf, key: key,
		mutate: func(r *http.Request, body []byte) {
			b := bytes.Clone(body)
			b[len(b)-1] ^= 1
			r.Body = io.NopCloser(bytes.NewReader(b))
			r.ContentLength = int64(len(b))
		}})
	if resp.StatusCode != http.StatusBadRequest || errCode(t, data) != signedsrv.CodeBadDigest {
		t.Fatalf("status %d body %s", resp.StatusCode, data)
	}
}

func TestIngest_RejectsReplay(t *testing.T) {
	f := newFixture(t, false)
	leaf, key := f.pki.leaf(t, "cluster-a")
	var first *http.Request
	var firstBody []byte
	resp, _ := f.do(t, call{path: signedsrv.PathIngest, msg: &pb.AlertPayload{ClusterId: "cluster-a"}, leaf: leaf, key: key,
		mutate: func(r *http.Request, body []byte) { first = r.Clone(context.Background()); firstBody = body }})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first status %d", resp.StatusCode)
	}
	first.Body = io.NopCloser(bytes.NewReader(firstBody))
	replay, err := http.DefaultClient.Do(first)
	if err != nil {
		t.Fatal(err)
	}
	defer replay.Body.Close()
	data, _ := io.ReadAll(replay.Body)
	if replay.StatusCode != http.StatusUnauthorized || errCode(t, data) != signedsrv.CodeReplay {
		t.Fatalf("status %d body %s", replay.StatusCode, data)
	}
}

func TestIngest_RejectsRevokedTenant(t *testing.T) {
	f := newFixture(t, true)
	leaf, key := f.pki.leaf(t, "cluster-a")
	resp, data := f.do(t, call{path: signedsrv.PathIngest, msg: &pb.AlertPayload{ClusterId: "cluster-a"}, leaf: leaf, key: key})
	if resp.StatusCode != http.StatusForbidden || errCode(t, data) != signedsrv.CodeRevoked {
		t.Fatalf("status %d body %s", resp.StatusCode, data)
	}
}

func TestIngest_RejectsUnknownTenant(t *testing.T) {
	f := newFixture(t, false)
	leaf, key := f.pki.leaf(t, "cluster-b")
	resp, data := f.do(t, call{path: signedsrv.PathIngest, msg: &pb.AlertPayload{ClusterId: "cluster-b"}, leaf: leaf, key: key})
	if resp.StatusCode != http.StatusForbidden || errCode(t, data) != signedsrv.CodeUnknownTenant {
		t.Fatalf("status %d body %s", resp.StatusCode, data)
	}
}

func TestIngest_UnknownHPKEKey(t *testing.T) {
	f := newFixture(t, false)
	leaf, key := f.pki.leaf(t, "cluster-a")
	resp, data := f.do(t, call{path: signedsrv.PathIngest, msg: &pb.AlertPayload{ClusterId: "cluster-a"}, leaf: leaf, key: key,
		mutate: func(r *http.Request, _ []byte) {
			// Re-sign with a kid the brain does not have.
			r.Header.Set(auth.HeaderHPKEKid, "ffffffffffffffff")
			created, _ := strconv.ParseInt(r.Header.Get(auth.HeaderTimestamp), 10, 64)
			_ = auth.SignRequest(r.Header, http.MethodPost, signedsrv.PathIngest, key, leaf.Raw, created)
		}})
	if resp.StatusCode != http.StatusBadRequest || errCode(t, data) != signedsrv.CodeHPKEKeyUnknown {
		t.Fatalf("status %d body %s", resp.StatusCode, data)
	}
}

func TestIngest_MapsHandlerErrors(t *testing.T) {
	f := newFixture(t, false)
	f.brain.ingestErr = status.Error(codes.PermissionDenied, "cluster mismatch")
	leaf, key := f.pki.leaf(t, "cluster-a")
	resp, data := f.do(t, call{path: signedsrv.PathIngest, msg: &pb.AlertPayload{ClusterId: "cluster-z"}, leaf: leaf, key: key})
	if resp.StatusCode != http.StatusForbidden || errCode(t, data) != signedsrv.CodeForbidden {
		t.Fatalf("status %d body %s", resp.StatusCode, data)
	}
}

func TestIngest_RejectsWrongContentType(t *testing.T) {
	f := newFixture(t, false)
	leaf, key := f.pki.leaf(t, "cluster-a")
	resp, _ := f.do(t, call{path: signedsrv.PathIngest, msg: &pb.AlertPayload{ClusterId: "cluster-a"}, leaf: leaf, key: key,
		mutate: func(r *http.Request, _ []byte) { r.Header.Set("Content-Type", "application/json") }})
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestKeys_SignedByIntermediate(t *testing.T) {
	f := newFixture(t, false)
	resp, err := http.Get(f.srv.URL + signedsrv.PathKeys)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var doc signedsrv.KeysDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	payload, _ := base64.StdEncoding.DecodeString(doc.Payload)
	sig, _ := base64.StdEncoding.DecodeString(doc.Signature)
	signerDER, _ := base64.StdEncoding.DecodeString(doc.Signer)
	signerCert, err := x509.ParseCertificate(signerDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(f.pki.rootCert)
	if _, err := signerCert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Fatalf("signer chain: %v", err)
	}
	if err := auth.VerifyPayload(signerCert, payload, sig); err != nil {
		t.Fatalf("payload signature: %v", err)
	}
	var kp signedsrv.KeysPayload
	if err := json.Unmarshal(payload, &kp); err != nil {
		t.Fatal(err)
	}
	if len(kp.Keys) != 1 || kp.Keys[0].KID != f.pub.KID || kp.Keys[0].KEM != auth.HPKEKEMName {
		t.Fatalf("keys payload %+v", kp)
	}
	raw, _ := base64.StdEncoding.DecodeString(kp.Keys[0].PublicKey)
	if pub, err := auth.ParseHPKEPublicKey(raw); err != nil || auth.HPKEKeyID(pub) != f.pub.KID {
		t.Fatalf("public key does not round-trip: %v", err)
	}
}
