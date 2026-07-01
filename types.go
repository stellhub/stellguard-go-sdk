package stellguard

import (
	"fmt"
	"strings"
	"time"

	agentv1 "github.com/stellhub/stellguard-go-sdk/proto/stellguard/agent/v1"
)

type CredentialRequest struct {
	SPIFFEID    string
	DNSNames    []string
	TTL         time.Duration
	ForceRotate bool
}

type CredentialBundle struct {
	CertificatePEM string
	PrivateKeyPEM  string
	TrustBundlePEM string
	Issuer         string
	KeyID          string
	SerialNumber   string
	ExpiresAt      time.Time
}

func (r CredentialRequest) validate() error {
	if strings.TrimSpace(r.SPIFFEID) == "" {
		return fmt.Errorf("spiffe ID is required")
	}
	if !strings.HasPrefix(r.SPIFFEID, "spiffe://") {
		return fmt.Errorf("spiffe ID must start with spiffe://")
	}
	if r.TTL < 0 {
		return fmt.Errorf("ttl cannot be negative")
	}
	return nil
}

func (r CredentialRequest) toProto() (*agentv1.FetchWorkloadCertificateRequest, error) {
	if err := r.validate(); err != nil {
		return nil, err
	}
	dnsNames := make([]string, 0, len(r.DNSNames))
	for _, dnsName := range r.DNSNames {
		value := strings.TrimSpace(dnsName)
		if value != "" {
			dnsNames = append(dnsNames, value)
		}
	}
	return &agentv1.FetchWorkloadCertificateRequest{
		SpiffeId:    strings.TrimSpace(r.SPIFFEID),
		DnsNames:    dnsNames,
		TtlSeconds:  int64(r.TTL / time.Second),
		ForceRotate: r.ForceRotate,
	}, nil
}

func credentialBundleFromProto(value *agentv1.CredentialBundle) *CredentialBundle {
	if value == nil {
		return nil
	}
	return &CredentialBundle{
		CertificatePEM: value.GetCertificatePem(),
		PrivateKeyPEM:  value.GetPrivateKeyPem(),
		TrustBundlePEM: value.GetTrustBundlePem(),
		Issuer:         value.GetIssuer(),
		KeyID:          value.GetKeyId(),
		SerialNumber:   value.GetSerialNumber(),
		ExpiresAt:      time.Unix(value.GetExpiresAtUnixSeconds(), 0).UTC(),
	}
}

func credentialBundleFromTrustBundle(value *agentv1.TrustBundle) *CredentialBundle {
	if value == nil {
		return nil
	}
	return &CredentialBundle{
		TrustBundlePEM: value.GetTrustBundlePem(),
		Issuer:         value.GetTrustDomain(),
		KeyID:          value.GetKeyId(),
	}
}
