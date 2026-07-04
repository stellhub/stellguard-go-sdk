package stellguard

import (
	"strings"
	"time"

	agentv1 "github.com/stellhub/stellguard-go-sdk/proto/stellguard/agent/v1"
)

func workloadCredentialFromProto(value *agentv1.WorkloadCredential) *WorkloadCredential {
	if value == nil {
		return nil
	}
	return &WorkloadCredential{
		Slot:                value.GetSlot(),
		CertificatePEM:      value.GetCertificatePem(),
		PrivateKeyPEM:       value.GetPrivateKeyPem(),
		CertificateChainPEM: value.GetCertificateChainPem(),
		TrustBundlePEM:      value.GetTrustBundlePem(),
		TrustDomain:         value.GetTrustDomain(),
		AgentID:             value.GetAgentId(),
		NodeID:              value.GetNodeId(),
		IdentityID:          value.GetIdentityId(),
		SessionID:           value.GetSessionId(),
		LeaseID:             value.GetLeaseId(),
		RenewalGroupID:      value.GetRenewalGroupId(),
		SPIFFEID:            value.GetSpiffeId(),
		DNSNames:            append([]string(nil), value.GetDnsNames()...),
		SerialNumber:        value.GetSerialNumber(),
		KeyVersionID:        value.GetKeyVersionId(),
		KeyVersionLabel:     value.GetKeyVersionLabel(),
		BundleID:            value.GetBundleId(),
		BundleVersion:       value.GetBundleVersion(),
		CertificateSHA256:   value.GetCertificateSha256(),
		NotBefore:           parseAgentTime(value.GetNotBefore()),
		NotAfter:            parseAgentTime(value.GetNotAfter()),
		RenewAfter:          parseAgentTime(value.GetRenewAfter()),
		UpdatedAt:           parseAgentTime(value.GetUpdatedAt()),
	}
}

func trustBundleFromProto(value *agentv1.TrustBundle) *TrustBundle {
	if value == nil {
		return nil
	}
	return &TrustBundle{
		TrustDomain:   value.GetTrustDomain(),
		BundleID:      value.GetBundleId(),
		BundleVersion: value.GetBundleVersion(),
		KeyVersionID:  value.GetKeyVersionId(),
		BundlePEM:     value.GetBundlePem(),
		UpdatedAt:     parseAgentTime(value.GetUpdatedAt()),
	}
}

func agentStatusFromProto(value *agentv1.AgentStatus) *AgentStatus {
	if value == nil {
		return nil
	}
	return &AgentStatus{
		State:         value.GetState(),
		Message:       value.GetMessage(),
		AgentID:       value.GetAgentId(),
		TrustDomain:   value.GetTrustDomain(),
		SessionID:     value.GetSessionId(),
		NodeID:        value.GetNodeId(),
		LastRenewalAt: parseAgentTime(value.GetLastRenewalAt()),
		LastError:     value.GetLastError(),
		UDSPath:       value.GetUdsPath(),
		StartedAt:     parseAgentTime(value.GetStartedAt()),
		BundleVersion: value.GetBundleVersion(),
		KeyVersionID:  value.GetKeyVersionId(),
	}
}

func parseAgentTime(value string) time.Time {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339Nano, trimmed)
	if err == nil {
		return parsed.UTC()
	}
	parsed, err = time.Parse(time.RFC3339, trimmed)
	if err == nil {
		return parsed.UTC()
	}
	return time.Time{}
}
