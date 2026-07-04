package stellguard

import (
	"context"
	"strings"
	"time"

	"github.com/stellhub/stellguard-go-sdk/internal/authn"
	"github.com/stellhub/stellguard-go-sdk/internal/observability"
)

func (c *Client) recordAuthentication(ctx context.Context, request AuthRequest, decision AuthDecision, start time.Time, agentDuration time.Duration) {
	if c == nil || c.metrics == nil {
		return
	}
	c.metrics.Record(ctx, observabilityRequest(request), observability.Decision{
		Allowed:       decision.Allowed,
		Bypassed:      decision.Bypassed,
		FailureKind:   string(decision.FailureKind),
		FailurePolicy: string(decision.FailurePolicy),
		AgentFailure:  isAgentFailure(decision.FailureKind),
	}, start, agentDuration)
}

func metricAttributesFromRequest(request AuthRequest) MetricAttributes {
	attributes := observability.RequestAttributes(observabilityRequest(request))
	return MetricAttributes(attributes)
}

func observabilityRequest(request AuthRequest) observability.Request {
	return observability.Request{
		Protocol:    request.Protocol,
		Method:      request.Method,
		Route:       request.Route,
		Operation:   request.Operation,
		ServiceName: request.ServiceName,
		SourceZone:  request.Source.Zone,
	}
}

func authnCredential(credential *WorkloadCredential) authn.Credential {
	if credential == nil {
		return authn.Credential{}
	}
	return authn.Credential{
		SPIFFEID:       credential.SPIFFEID,
		TrustDomain:    credential.TrustDomain,
		TrustBundlePEM: credential.TrustBundlePEM,
		CertificatePEM: credential.CertificatePEM,
	}
}

func authnRequest(request AuthRequest) authn.Request {
	return authn.Request{
		PeerCertificatePEM: request.PeerCertificatePEM,
		ExpectedPrincipal:  request.ExpectedPrincipal,
		AllowedPrincipals:  request.AllowedPrincipals,
		Attributes:         request.Attributes,
	}
}

func failureKindFromAuthn(kind authn.FailureKind) FailureKind {
	switch kind {
	case authn.FailureNone:
		return FailureNone
	case authn.FailureUnauthenticated:
		return FailureUnauthenticated
	case authn.FailureUnauthorized:
		return FailureUnauthorized
	case authn.FailureAgentError:
		return FailureAgentError
	default:
		return FailureAgentError
	}
}

func requestRoute(request AuthRequest) string {
	if value := strings.TrimSpace(request.Route); value != "" {
		return value
	}
	if value := strings.TrimSpace(request.Operation); value != "" {
		return value
	}
	return "unknown"
}

func cleanMetricValue(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "unknown"
	}
	return trimmed
}
