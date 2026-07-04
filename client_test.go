package stellguard

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	agentv1 "github.com/stellhub/stellguard-go-sdk/proto/stellguard/agent/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

const bufSize = 1024 * 1024

type fakeWorkloadServer struct {
	agentv1.UnimplementedWorkloadCredentialServiceServer

	fetchErr          error
	credential        *agentv1.WorkloadCredential
	trustBundle       *agentv1.TrustBundle
	agentStatus       *agentv1.AgentStatus
	seenAuth          string
	seenAudience      string
	seenPrivateKeyOpt *bool
}

func (s *fakeWorkloadServer) FetchWorkloadCredential(ctx context.Context, request *agentv1.FetchWorkloadCredentialRequest) (*agentv1.WorkloadCredential, error) {
	if values := metadata.ValueFromIncomingContext(ctx, "authorization"); len(values) > 0 {
		s.seenAuth = values[0]
	}
	s.seenAudience = request.GetAudience()
	s.seenPrivateKeyOpt = request.IncludePrivateKey
	if s.fetchErr != nil {
		return nil, s.fetchErr
	}
	if s.credential != nil {
		return s.credential, nil
	}
	return &agentv1.WorkloadCredential{
		Slot:              "current",
		SpiffeId:          "spiffe://stell.local/ns/default/sa/api",
		IdentityId:        "identity-api",
		TrustDomain:       "stell.local",
		TrustBundlePem:    testStaticTrustBundlePEM,
		BundleVersion:     3,
		CertificateSha256: "abc123",
		NotAfter:          time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano),
	}, nil
}

func (s *fakeWorkloadServer) WatchWorkloadCredential(_ *agentv1.WatchWorkloadCredentialRequest, stream agentv1.WorkloadCredentialService_WatchWorkloadCredentialServer) error {
	<-stream.Context().Done()
	return stream.Context().Err()
}

func (s *fakeWorkloadServer) GetTrustBundle(context.Context, *agentv1.GetTrustBundleRequest) (*agentv1.TrustBundle, error) {
	if s.trustBundle != nil {
		return s.trustBundle, nil
	}
	return &agentv1.TrustBundle{
		TrustDomain:   "stell.local",
		BundleId:      "bundle-1",
		BundleVersion: 3,
		KeyVersionId:  "key-1",
		BundlePem:     "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
		UpdatedAt:     time.Now().UTC().Format(time.RFC3339Nano),
	}, nil
}

func (s *fakeWorkloadServer) GetAgentStatus(context.Context, *agentv1.GetAgentStatusRequest) (*agentv1.AgentStatus, error) {
	if s.agentStatus != nil {
		return s.agentStatus, nil
	}
	return &agentv1.AgentStatus{
		State:         "ready",
		AgentId:       "agent-1",
		TrustDomain:   "stell.local",
		UdsPath:       "/var/run/stellguard/agent.sock",
		BundleVersion: 3,
		KeyVersionId:  "key-1",
		StartedAt:     time.Now().UTC().Format(time.RFC3339Nano),
	}, nil
}

func TestAuthenticateAllowsWithCredential(t *testing.T) {
	credential, peerCertificatePEM := newTestCredentialAndPeerCertificate(t, "stell.local", "spiffe://stell.local/ns/default/sa/client")
	server := &fakeWorkloadServer{credential: credential}
	conn, cleanup := newBufconnClient(t, server)
	defer cleanup()

	client := NewWithConn(conn, Options{
		AgentToken:     "secret",
		MetricsEnabled: Bool(false),
		TracesEnabled:  Bool(false),
	})

	decision, err := client.Authenticate(context.Background(), AuthRequest{
		Audience:           "spiffe://stell.local/ns/default/sa/api",
		PeerCertificatePEM: peerCertificatePEM,
		Protocol:           "http",
		Method:             "GET",
		Route:              "/api/orders/{id}",
		ServiceName:        "order-api",
	})
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if !decision.Allowed {
		t.Fatalf("expected allowed decision, got %+v", decision)
	}
	if decision.FailureKind != FailureNone {
		t.Fatalf("unexpected failure kind %q", decision.FailureKind)
	}
	if decision.Principal != "spiffe://stell.local/ns/default/sa/client" {
		t.Fatalf("unexpected principal %q", decision.Principal)
	}
	if decision.LocalPrincipal != "spiffe://stell.local/ns/default/sa/api" {
		t.Fatalf("unexpected local principal %q", decision.LocalPrincipal)
	}
	if decision.IdentityID != "identity-api" {
		t.Fatalf("unexpected identity ID %q", decision.IdentityID)
	}
	if decision.PolicyID != "" {
		t.Fatalf("policy ID should stay empty when agent does not provide one, got %q", decision.PolicyID)
	}
	if server.seenAuth != "Bearer secret" {
		t.Fatalf("unexpected authorization metadata %q", server.seenAuth)
	}
	if server.seenAudience != "spiffe://stell.local/ns/default/sa/api" {
		t.Fatalf("unexpected audience %q", server.seenAudience)
	}
	if server.seenPrivateKeyOpt == nil || *server.seenPrivateKeyOpt {
		t.Fatalf("Authenticate should request credential without private key")
	}
}

func TestAuthenticateDeniesPeerCertificateWithoutClientAuthUsage(t *testing.T) {
	credential, peerCertificatePEM := newTestCredentialAndPeerCertificateWithPeerUsages(
		t,
		"stell.local",
		"spiffe://stell.local/ns/default/sa/client",
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	)
	server := &fakeWorkloadServer{credential: credential}
	conn, cleanup := newBufconnClient(t, server)
	defer cleanup()

	client := NewWithConn(conn, Options{
		MetricsEnabled: Bool(false),
		TracesEnabled:  Bool(false),
	})

	decision, err := client.Authenticate(context.Background(), AuthRequest{
		Audience:           "spiffe://stell.local/ns/default/sa/api",
		PeerCertificatePEM: peerCertificatePEM,
	})
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if decision.Allowed {
		t.Fatalf("expected non client-auth peer certificate to be denied, got %+v", decision)
	}
	if decision.FailureKind != FailureUnauthorized {
		t.Fatalf("unexpected failure kind %q", decision.FailureKind)
	}
}

func TestAuthenticateDeniesMissingPeerCertificateByDefault(t *testing.T) {
	credential, _ := newTestCredentialAndPeerCertificate(t, "stell.local", "spiffe://stell.local/ns/default/sa/client")
	server := &fakeWorkloadServer{credential: credential}
	conn, cleanup := newBufconnClient(t, server)
	defer cleanup()

	client := NewWithConn(conn, Options{
		MetricsEnabled: Bool(false),
		TracesEnabled:  Bool(false),
	})

	decision, err := client.Authenticate(context.Background(), AuthRequest{
		Audience: "spiffe://stell.local/ns/default/sa/api",
	})
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if decision.Allowed {
		t.Fatalf("expected missing peer certificate to be denied, got %+v", decision)
	}
	if decision.FailureKind != FailureUnauthenticated {
		t.Fatalf("unexpected failure kind %q", decision.FailureKind)
	}
}

func TestAuthenticateDeniesUnexpectedPeerPrincipal(t *testing.T) {
	credential, peerCertificatePEM := newTestCredentialAndPeerCertificate(t, "stell.local", "spiffe://stell.local/ns/default/sa/client")
	server := &fakeWorkloadServer{credential: credential}
	conn, cleanup := newBufconnClient(t, server)
	defer cleanup()

	client := NewWithConn(conn, Options{
		MetricsEnabled: Bool(false),
		TracesEnabled:  Bool(false),
	})

	decision, err := client.Authenticate(context.Background(), AuthRequest{
		Audience:           "spiffe://stell.local/ns/default/sa/api",
		PeerCertificatePEM: peerCertificatePEM,
		ExpectedPrincipal:  "spiffe://stell.local/ns/default/sa/other",
	})
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if decision.Allowed {
		t.Fatalf("expected unexpected peer principal to be denied, got %+v", decision)
	}
	if decision.FailureKind != FailureUnauthorized {
		t.Fatalf("unexpected failure kind %q", decision.FailureKind)
	}
}

func TestAuthenticateClassifiesInvalidAgentCredential(t *testing.T) {
	server := &fakeWorkloadServer{credential: &agentv1.WorkloadCredential{}}
	conn, cleanup := newBufconnClient(t, server)
	defer cleanup()

	client := NewWithConn(conn, Options{
		MetricsEnabled: Bool(false),
		TracesEnabled:  Bool(false),
	})

	decision, err := client.Authenticate(context.Background(), AuthRequest{})
	if err == nil {
		t.Fatal("expected invalid agent credential error")
	}
	if decision.FailureKind != FailureAgentError {
		t.Fatalf("unexpected failure kind %q", decision.FailureKind)
	}
	if !decision.Allowed || !decision.Bypassed {
		t.Fatalf("expected default agent error bypass, got %+v", decision)
	}
}

func TestAuthenticateClassifiesLocalCredentialTrustDomainMismatch(t *testing.T) {
	credential, peerCertificatePEM := newTestCredentialAndPeerCertificate(t, "stell.local", "spiffe://stell.local/ns/default/sa/client")
	credential.TrustDomain = "other.local"
	server := &fakeWorkloadServer{credential: credential}
	conn, cleanup := newBufconnClient(t, server)
	defer cleanup()

	client := NewWithConn(conn, Options{
		MetricsEnabled: Bool(false),
		TracesEnabled:  Bool(false),
	})

	decision, err := client.Authenticate(context.Background(), AuthRequest{
		PeerCertificatePEM: peerCertificatePEM,
	})
	if err == nil {
		t.Fatal("expected invalid agent credential error")
	}
	if decision.FailureKind != FailureAgentError {
		t.Fatalf("unexpected failure kind %q", decision.FailureKind)
	}
}

func TestAuthenticateDeniedAfterClientClose(t *testing.T) {
	credential, peerCertificatePEM := newTestCredentialAndPeerCertificate(t, "stell.local", "spiffe://stell.local/ns/default/sa/client")
	server := &fakeWorkloadServer{credential: credential}
	conn, cleanup := newBufconnClient(t, server)
	defer cleanup()

	client := NewWithConn(conn, Options{
		MetricsEnabled: Bool(false),
		TracesEnabled:  Bool(false),
	})
	if err := client.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	decision, err := client.Authenticate(context.Background(), AuthRequest{
		PeerCertificatePEM: peerCertificatePEM,
	})
	if !errors.Is(err, ErrClientClosed) {
		t.Fatalf("expected ErrClientClosed, got %v", err)
	}
	if decision.Allowed {
		t.Fatalf("closed client must not fail open, got %+v", decision)
	}
	if decision.FailureKind != FailureClientClosed {
		t.Fatalf("unexpected failure kind %q", decision.FailureKind)
	}
}

func TestAuthenticateDeniedWhenContextCanceled(t *testing.T) {
	credential, peerCertificatePEM := newTestCredentialAndPeerCertificate(t, "stell.local", "spiffe://stell.local/ns/default/sa/client")
	server := &fakeWorkloadServer{credential: credential}
	conn, cleanup := newBufconnClient(t, server)
	defer cleanup()

	client := NewWithConn(conn, Options{
		MetricsEnabled: Bool(false),
		TracesEnabled:  Bool(false),
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	decision, err := client.Authenticate(ctx, AuthRequest{
		PeerCertificatePEM: peerCertificatePEM,
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if decision.Allowed {
		t.Fatalf("canceled request must not fail open, got %+v", decision)
	}
	if decision.FailureKind != FailureRequestCanceled {
		t.Fatalf("unexpected failure kind %q", decision.FailureKind)
	}
	if server.seenAudience != "" {
		t.Fatalf("canceled request should not call agent, saw audience %q", server.seenAudience)
	}
}

func TestAuthenticateDeniesPermissionDeniedByDefault(t *testing.T) {
	server := &fakeWorkloadServer{
		fetchErr: status.Error(codes.PermissionDenied, "audience mismatch"),
	}
	conn, cleanup := newBufconnClient(t, server)
	defer cleanup()

	client := NewWithConn(conn, Options{
		MetricsEnabled: Bool(false),
		TracesEnabled:  Bool(false),
	})

	decision, err := client.Authenticate(context.Background(), AuthRequest{Audience: "wrong"})
	if err != nil {
		t.Fatalf("Authenticate() should classify permission denied without returning transport error, got %v", err)
	}
	if decision.Allowed {
		t.Fatalf("expected denied decision, got %+v", decision)
	}
	if decision.FailureKind != FailureUnauthorized {
		t.Fatalf("unexpected failure kind %q", decision.FailureKind)
	}
	if decision.FailurePolicy != FailurePolicyDeny {
		t.Fatalf("unexpected failure policy %q", decision.FailurePolicy)
	}
}

func TestAuthenticateCanSkipPeerCertificateForReadinessMode(t *testing.T) {
	credential, _ := newTestCredentialAndPeerCertificate(t, "stell.local", "spiffe://stell.local/ns/default/sa/client")
	server := &fakeWorkloadServer{credential: credential}
	conn, cleanup := newBufconnClient(t, server)
	defer cleanup()

	client := NewWithConn(conn, Options{
		RequirePeerCertificate: Bool(false),
		MetricsEnabled:         Bool(false),
		TracesEnabled:          Bool(false),
	})

	decision, err := client.Authenticate(context.Background(), AuthRequest{})
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if !decision.Allowed {
		t.Fatalf("expected readiness mode to allow with local credential, got %+v", decision)
	}
	if decision.Principal != "spiffe://stell.local/ns/default/sa/api" {
		t.Fatalf("unexpected principal %q", decision.Principal)
	}
}

func TestAuthenticateCanBypassRealAuthFailure(t *testing.T) {
	server := &fakeWorkloadServer{
		fetchErr: status.Error(codes.Unauthenticated, "missing local identity"),
	}
	conn, cleanup := newBufconnClient(t, server)
	defer cleanup()

	client := NewWithConn(conn, Options{
		AuthFailurePolicy: FailurePolicyAllow,
		MetricsEnabled:    Bool(false),
		TracesEnabled:     Bool(false),
	})

	decision, err := client.Authenticate(context.Background(), AuthRequest{})
	if err != nil {
		t.Fatalf("Authenticate() should classify unauthenticated without returning transport error, got %v", err)
	}
	if !decision.Allowed || !decision.Bypassed {
		t.Fatalf("expected bypassed auth failure, got %+v", decision)
	}
	if decision.FailureKind != FailureUnauthenticated {
		t.Fatalf("unexpected failure kind %q", decision.FailureKind)
	}
}

func TestAuthenticateAllowsAgentFailureByDefault(t *testing.T) {
	server := &fakeWorkloadServer{
		fetchErr: status.Error(codes.Unavailable, "agent unavailable"),
	}
	conn, cleanup := newBufconnClient(t, server)
	defer cleanup()

	client := NewWithConn(conn, Options{
		MetricsEnabled: Bool(false),
		TracesEnabled:  Bool(false),
	})

	decision, err := client.Authenticate(context.Background(), AuthRequest{})
	if err == nil {
		t.Fatal("expected agent failure error")
	}
	if !decision.Allowed || !decision.Bypassed {
		t.Fatalf("expected default agent failure bypass, got %+v", decision)
	}
	if decision.FailureKind != FailureAgentUnavailable {
		t.Fatalf("unexpected failure kind %q", decision.FailureKind)
	}
	if decision.FailurePolicy != FailurePolicyAllow {
		t.Fatalf("unexpected failure policy %q", decision.FailurePolicy)
	}
}

func TestAuthenticateClassifiesServerCanceledAsAgentError(t *testing.T) {
	server := &fakeWorkloadServer{
		fetchErr: status.Error(codes.Canceled, "server canceled request"),
	}
	conn, cleanup := newBufconnClient(t, server)
	defer cleanup()

	client := NewWithConn(conn, Options{
		MetricsEnabled: Bool(false),
		TracesEnabled:  Bool(false),
	})

	decision, err := client.Authenticate(context.Background(), AuthRequest{})
	if err == nil {
		t.Fatal("expected canceled error")
	}
	if !decision.Allowed || !decision.Bypassed {
		t.Fatalf("expected server-side cancel to follow agent failure policy, got %+v", decision)
	}
	if decision.FailureKind != FailureAgentError {
		t.Fatalf("unexpected failure kind %q", decision.FailureKind)
	}
}

func TestAuthenticateCanDenyAgentFailure(t *testing.T) {
	server := &fakeWorkloadServer{
		fetchErr: status.Error(codes.DeadlineExceeded, "agent timeout"),
	}
	conn, cleanup := newBufconnClient(t, server)
	defer cleanup()

	client := NewWithConn(conn, Options{
		AgentFailurePolicy: FailurePolicyDeny,
		MetricsEnabled:     Bool(false),
		TracesEnabled:      Bool(false),
	})

	decision, err := client.Authenticate(context.Background(), AuthRequest{})
	if err == nil {
		t.Fatal("expected agent timeout error")
	}
	if decision.Allowed {
		t.Fatalf("expected denied agent failure, got %+v", decision)
	}
	if decision.FailureKind != FailureAgentTimeout {
		t.Fatalf("unexpected failure kind %q", decision.FailureKind)
	}
}

func TestFetchWorkloadCredentialAndTrustBundle(t *testing.T) {
	server := &fakeWorkloadServer{}
	conn, cleanup := newBufconnClient(t, server)
	defer cleanup()

	client := NewWithConn(conn, Options{
		MetricsEnabled: Bool(false),
		TracesEnabled:  Bool(false),
	})

	credential, err := client.FetchWorkloadCredential(context.Background(), WorkloadCredentialRequest{
		Audience:          "spiffe://stell.local/ns/default/sa/api",
		IncludePrivateKey: Bool(true),
	})
	if err != nil {
		t.Fatalf("FetchWorkloadCredential() error = %v", err)
	}
	if credential.TrustDomain != "stell.local" {
		t.Fatalf("unexpected trust domain %q", credential.TrustDomain)
	}

	bundle, err := client.GetTrustBundle(context.Background(), TrustBundleRequest{TrustDomain: "stell.local"})
	if err != nil {
		t.Fatalf("GetTrustBundle() error = %v", err)
	}
	if bundle.BundleID != "bundle-1" {
		t.Fatalf("unexpected bundle ID %q", bundle.BundleID)
	}
}

func TestGetAgentStatus(t *testing.T) {
	server := &fakeWorkloadServer{}
	conn, cleanup := newBufconnClient(t, server)
	defer cleanup()

	client := NewWithConn(conn, Options{
		MetricsEnabled: Bool(false),
		TracesEnabled:  Bool(false),
	})

	status, err := client.GetAgentStatus(context.Background())
	if err != nil {
		t.Fatalf("GetAgentStatus() error = %v", err)
	}
	if status.State != "ready" {
		t.Fatalf("unexpected state %q", status.State)
	}
}

func TestWatcherCloseCancelsStream(t *testing.T) {
	server := &fakeWorkloadServer{}
	conn, cleanup := newBufconnClient(t, server)
	defer cleanup()

	client := NewWithConn(conn, Options{
		MetricsEnabled: Bool(false),
		TracesEnabled:  Bool(false),
	})

	watcher, err := client.WatchWorkloadCredential(context.Background(), WatchWorkloadCredentialRequest{})
	if err != nil {
		t.Fatalf("WatchWorkloadCredential() error = %v", err)
	}
	if err := watcher.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if _, err := watcher.Recv(); err == nil || errors.Is(err, io.EOF) {
		t.Fatalf("expected canceled watch stream error, got %v", err)
	}
}

func TestDialRejectsNonUnixTarget(t *testing.T) {
	_, err := Dial(context.Background(), Options{
		AgentTarget: "127.0.0.1:9443",
	})
	if err == nil {
		t.Fatal("expected non-unix target to be rejected")
	}
}

func newBufconnClient(t *testing.T, workloadServer agentv1.WorkloadCredentialServiceServer) (*grpc.ClientConn, func()) {
	t.Helper()

	listener := bufconn.Listen(bufSize)
	grpcServer := grpc.NewServer()
	agentv1.RegisterWorkloadCredentialServiceServer(grpcServer, workloadServer)

	go func() {
		_ = grpcServer.Serve(listener)
	}()

	dialer := func(context.Context, string) (net.Conn, error) {
		return listener.Dial()
	}
	conn, err := grpc.DialContext(
		context.Background(),
		"bufnet",
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}

	cleanup := func() {
		_ = conn.Close()
		grpcServer.Stop()
		_ = listener.Close()
	}
	return conn, cleanup
}

const testStaticTrustBundlePEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"

func newTestCredentialAndPeerCertificate(t *testing.T, trustDomain, peerSPIFFEID string) (*agentv1.WorkloadCredential, string) {
	return newTestCredentialAndPeerCertificateWithPeerUsages(t, trustDomain, peerSPIFFEID, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
}

func newTestCredentialAndPeerCertificateWithPeerUsages(t *testing.T, trustDomain, peerSPIFFEID string, peerUsages []x509.ExtKeyUsage) (*agentv1.WorkloadCredential, string) {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey(ca) error = %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "stellguard-test-ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate(ca) error = %v", err)
	}

	peerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey(peer) error = %v", err)
	}
	peerURI, err := url.Parse(peerSPIFFEID)
	if err != nil {
		t.Fatalf("Parse(%q) error = %v", peerSPIFFEID, err)
	}
	peerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "stellguard-test-peer"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  peerUsages,
		URIs:         []*url.URL{peerURI},
	}
	peerDER, err := x509.CreateCertificate(rand.Reader, peerTemplate, caTemplate, &peerKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate(peer) error = %v", err)
	}

	localKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey(local) error = %v", err)
	}
	localSPIFFEID := "spiffe://" + trustDomain + "/ns/default/sa/api"
	localURI, err := url.Parse(localSPIFFEID)
	if err != nil {
		t.Fatalf("Parse(%q) error = %v", localSPIFFEID, err)
	}
	localTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "stellguard-test-local"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		URIs:         []*url.URL{localURI},
	}
	localDER, err := x509.CreateCertificate(rand.Reader, localTemplate, caTemplate, &localKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate(local) error = %v", err)
	}

	trustBundlePEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	peerCertificatePEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: peerDER}))
	localCertificatePEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: localDER}))
	return &agentv1.WorkloadCredential{
		Slot:           "current",
		CertificatePem: localCertificatePEM,
		SpiffeId:       localSPIFFEID,
		IdentityId:     "identity-api",
		TrustDomain:    trustDomain,
		TrustBundlePem: trustBundlePEM,
		BundleVersion:  3,
		NotAfter:       time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano),
	}, peerCertificatePEM
}
