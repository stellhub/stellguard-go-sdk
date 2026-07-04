package stellguard

import (
	"context"
	"sync"
	"time"
)

type AuthClient interface {
	Authenticate(ctx context.Context, request AuthRequest) (AuthDecision, error)
	Close() error
}

type AuthRequest struct {
	RequestID          string
	Protocol           string
	Method             string
	Path               string
	Route              string
	Operation          string
	Audience           string
	PeerCertificatePEM string
	ExpectedPrincipal  string
	AllowedPrincipals  []string
	Source             RequestSource
	ServiceName        string
	ServiceNamespace   string
	ServiceInstanceID  string
	Headers            map[string]string
	Attributes         map[string]string
}

type RequestSource struct {
	IP           string
	Port         string
	ForwardedFor string
	UserAgent    string
	Authority    string
	Zone         string
}

type AuthDecision struct {
	Allowed        bool
	Bypassed       bool
	FailureKind    FailureKind
	FailurePolicy  FailurePolicy
	Reason         string
	Principal      string
	LocalPrincipal string
	IdentityID     string
	PolicyID       string
	Source         RequestSource
	Metrics        MetricAttributes
}

type MetricAttributes map[string]string

type FailureKind string

const (
	FailureNone             FailureKind = "none"
	FailureUnauthenticated  FailureKind = "unauthenticated"
	FailureUnauthorized     FailureKind = "unauthorized"
	FailureAgentUnavailable FailureKind = "agent_unavailable"
	FailureAgentTimeout     FailureKind = "agent_timeout"
	FailureAgentError       FailureKind = "agent_error"
	FailureInvalidRequest   FailureKind = "invalid_request"
	FailureClientClosed     FailureKind = "client_closed"
	FailureRequestCanceled  FailureKind = "request_canceled"
)

type FailurePolicy string

const (
	FailurePolicyAllow FailurePolicy = "allow"
	FailurePolicyDeny  FailurePolicy = "deny"
)

type WorkloadCredentialRequest struct {
	Audience          string
	IncludePrivateKey *bool
}

type WatchWorkloadCredentialRequest struct {
	SendCurrent       *bool
	Audience          string
	IncludePrivateKey *bool
}

type TrustBundleRequest struct {
	TrustDomain string
}

type WorkloadCredential struct {
	Slot                string
	CertificatePEM      string
	PrivateKeyPEM       string
	CertificateChainPEM string
	TrustBundlePEM      string
	TrustDomain         string
	AgentID             string
	NodeID              string
	IdentityID          string
	SessionID           string
	LeaseID             string
	RenewalGroupID      string
	SPIFFEID            string
	DNSNames            []string
	SerialNumber        string
	KeyVersionID        string
	KeyVersionLabel     string
	BundleID            string
	BundleVersion       int64
	CertificateSHA256   string
	NotBefore           time.Time
	NotAfter            time.Time
	RenewAfter          time.Time
	UpdatedAt           time.Time
}

type TrustBundle struct {
	TrustDomain   string
	BundleID      string
	BundleVersion int64
	KeyVersionID  string
	BundlePEM     string
	UpdatedAt     time.Time
}

type AgentStatus struct {
	State         string
	Message       string
	AgentID       string
	TrustDomain   string
	SessionID     string
	NodeID        string
	LastRenewalAt time.Time
	LastError     string
	UDSPath       string
	StartedAt     time.Time
	BundleVersion int64
	KeyVersionID  string
}

type WorkloadCredentialWatcher struct {
	once  sync.Once
	recv  func() (*WorkloadCredential, error)
	close func() error
}

func (w *WorkloadCredentialWatcher) Recv() (*WorkloadCredential, error) {
	if w == nil || w.recv == nil {
		return nil, ErrClientClosed
	}
	return w.recv()
}

func (w *WorkloadCredentialWatcher) Close() error {
	if w == nil || w.close == nil {
		return nil
	}
	var err error
	w.once.Do(func() {
		err = w.close()
	})
	return err
}

func Bool(value bool) *bool {
	return &value
}
