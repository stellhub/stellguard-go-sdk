package authn

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	AttributePeerCertificatePEM    = "tls.peer.certificate_pem"
	AttributePeerCertificatePEMAlt = "peer.certificate_pem"
	AttributePeerCertificateX509   = "x509.peer.certificate_pem"
)

var ErrInvalidCredential = errors.New("stellguard agent returned invalid workload credential")

type FailureKind string

const (
	FailureNone            FailureKind = "none"
	FailureUnauthenticated FailureKind = "unauthenticated"
	FailureUnauthorized    FailureKind = "unauthorized"
	FailureAgentError      FailureKind = "agent_error"
)

type Credential struct {
	SPIFFEID       string
	TrustDomain    string
	TrustBundlePEM string
	CertificatePEM string
}

type Request struct {
	PeerCertificatePEM string
	ExpectedPrincipal  string
	AllowedPrincipals  []string
	Attributes         map[string]string
}

type Result struct {
	Principal   string
	FailureKind FailureKind
	Reason      string
}

func ValidateCredential(credential Credential) error {
	if strings.TrimSpace(credential.SPIFFEID) == "" {
		return fmt.Errorf("%w: missing local spiffe id", ErrInvalidCredential)
	}
	if strings.TrimSpace(credential.TrustDomain) == "" {
		return fmt.Errorf("%w: missing trust domain", ErrInvalidCredential)
	}
	if strings.TrimSpace(credential.TrustBundlePEM) == "" {
		return fmt.Errorf("%w: missing trust bundle", ErrInvalidCredential)
	}
	if strings.TrimSpace(credential.CertificatePEM) == "" {
		return fmt.Errorf("%w: missing local certificate", ErrInvalidCredential)
	}
	if !sameTrustDomain(credential.SPIFFEID, credential.TrustDomain) {
		return fmt.Errorf("%w: local spiffe id trust domain mismatch", ErrInvalidCredential)
	}
	if _, err := parseCertificatePool(credential.TrustBundlePEM); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidCredential, err)
	}
	certificates, err := parseCertificates(credential.CertificatePEM)
	if err != nil {
		return fmt.Errorf("%w: invalid local certificate: %v", ErrInvalidCredential, err)
	}
	if len(certificates) == 0 {
		return fmt.Errorf("%w: local certificate is required", ErrInvalidCredential)
	}
	localPrincipal := spiffeIDFromCertificate(certificates[0])
	if localPrincipal == "" {
		return fmt.Errorf("%w: local certificate has no spiffe id", ErrInvalidCredential)
	}
	if localPrincipal != strings.TrimSpace(credential.SPIFFEID) {
		return fmt.Errorf("%w: local certificate spiffe id mismatch", ErrInvalidCredential)
	}
	return nil
}

func VerifyRequest(request Request, credential Credential, now time.Time) Result {
	peerPEM := requestPeerCertificatePEM(request)
	if strings.TrimSpace(peerPEM) == "" {
		return Result{FailureKind: FailureUnauthenticated, Reason: "request peer certificate is required"}
	}

	roots, err := parseCertificatePool(credential.TrustBundlePEM)
	if err != nil {
		return Result{FailureKind: FailureAgentError, Reason: "agent trust bundle is invalid"}
	}
	certificates, err := parseCertificates(peerPEM)
	if err != nil {
		return Result{FailureKind: FailureUnauthenticated, Reason: "request peer certificate is invalid"}
	}
	if len(certificates) == 0 {
		return Result{FailureKind: FailureUnauthenticated, Reason: "request peer certificate is required"}
	}

	intermediates := x509.NewCertPool()
	for _, certificate := range certificates[1:] {
		intermediates.AddCert(certificate)
	}
	if _, err := certificates[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return Result{FailureKind: FailureUnauthorized, Reason: "request peer certificate is not trusted"}
	}

	principal := spiffeIDFromCertificate(certificates[0])
	if principal == "" {
		return Result{FailureKind: FailureUnauthenticated, Reason: "request peer certificate has no spiffe id"}
	}
	if !sameTrustDomain(principal, credential.TrustDomain) {
		return Result{FailureKind: FailureUnauthorized, Reason: "request peer certificate trust domain mismatch"}
	}
	if !principalAllowed(principal, request) {
		return Result{FailureKind: FailureUnauthorized, Reason: "request peer principal is not allowed"}
	}
	return Result{Principal: principal, FailureKind: FailureNone, Reason: "authenticated"}
}

func requestPeerCertificatePEM(request Request) string {
	if value := strings.TrimSpace(request.PeerCertificatePEM); value != "" {
		return value
	}
	for _, key := range []string{
		AttributePeerCertificatePEM,
		AttributePeerCertificatePEMAlt,
		AttributePeerCertificateX509,
	} {
		if value := strings.TrimSpace(request.Attributes[key]); value != "" {
			return value
		}
	}
	return ""
}

func parseCertificatePool(value string) (*x509.CertPool, error) {
	certificates, err := parseCertificates(value)
	if err != nil {
		return nil, err
	}
	if len(certificates) == 0 {
		return nil, fmt.Errorf("no certificates found")
	}
	pool := x509.NewCertPool()
	for _, certificate := range certificates {
		pool.AddCert(certificate)
	}
	return pool, nil
}

func parseCertificates(value string) ([]*x509.Certificate, error) {
	remaining := []byte(value)
	certificates := make([]*x509.Certificate, 0)
	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		remaining = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, certificate)
	}
	return certificates, nil
}

func spiffeIDFromCertificate(certificate *x509.Certificate) string {
	if certificate == nil {
		return ""
	}
	for _, uri := range certificate.URIs {
		if uri != nil && uri.Scheme == "spiffe" && uri.Host != "" {
			return uri.String()
		}
	}
	return ""
}

func sameTrustDomain(spiffeID, trustDomain string) bool {
	parsed, err := url.Parse(spiffeID)
	if err != nil {
		return false
	}
	return parsed.Scheme == "spiffe" && parsed.Host == strings.TrimSpace(trustDomain)
}

func principalAllowed(principal string, request Request) bool {
	if expected := strings.TrimSpace(request.ExpectedPrincipal); expected != "" {
		return principal == expected
	}
	if len(request.AllowedPrincipals) == 0 {
		return true
	}
	for _, allowed := range request.AllowedPrincipals {
		if principal == strings.TrimSpace(allowed) {
			return true
		}
	}
	return false
}
