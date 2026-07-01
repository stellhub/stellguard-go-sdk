package stellguard

import (
	"context"
	"net"
	"testing"
	"time"

	agentv1 "github.com/stellhub/stellguard-go-sdk/proto/stellguard/agent/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
)

const bufSize = 1024 * 1024

type fakeAgentServer struct {
	agentv1.UnimplementedStellGuardAgentServer
	seenAuth string
}

func (s *fakeAgentServer) FetchWorkloadCertificate(ctx context.Context, request *agentv1.FetchWorkloadCertificateRequest) (*agentv1.CredentialBundle, error) {
	if values := metadata.ValueFromIncomingContext(ctx, "authorization"); len(values) > 0 {
		s.seenAuth = values[0]
	}
	return &agentv1.CredentialBundle{
		CertificatePem:       "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
		PrivateKeyPem:        "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n",
		TrustBundlePem:       "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
		Issuer:               "stell.local",
		KeyId:                "key-1",
		SerialNumber:         "42",
		ExpiresAtUnixSeconds: time.Now().Add(time.Minute).Unix(),
	}, nil
}

func TestFetchWorkloadCertificate(t *testing.T) {
	server := &fakeAgentServer{}
	conn, cleanup := newBufconnClient(t, server)
	defer cleanup()

	client := NewWithConn(conn, Options{
		AgentToken: "secret",
		Timeout:    time.Second,
	})

	bundle, err := client.FetchWorkloadCertificate(context.Background(), CredentialRequest{
		SPIFFEID: "spiffe://stell.local/workload/api",
		DNSNames: []string{" api.local ", ""},
		TTL:      time.Minute,
	})
	if err != nil {
		t.Fatalf("FetchWorkloadCertificate() error = %v", err)
	}
	if bundle.KeyID != "key-1" {
		t.Fatalf("unexpected key ID %q", bundle.KeyID)
	}
	if server.seenAuth != "Bearer secret" {
		t.Fatalf("unexpected authorization metadata %q", server.seenAuth)
	}
}

func TestCredentialRequestValidation(t *testing.T) {
	_, err := CredentialRequest{SPIFFEID: "https://stell.local/workload/api"}.toProto()
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func newBufconnClient(t *testing.T, agentServer agentv1.StellGuardAgentServer) (*grpc.ClientConn, func()) {
	t.Helper()

	listener := bufconn.Listen(bufSize)
	grpcServer := grpc.NewServer()
	agentv1.RegisterStellGuardAgentServer(grpcServer, agentServer)

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
