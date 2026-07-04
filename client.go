package stellguard

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/stellhub/stellguard-go-sdk/internal/agenttransport"
	"github.com/stellhub/stellguard-go-sdk/internal/authn"
	"github.com/stellhub/stellguard-go-sdk/internal/observability"
	agentv1 "github.com/stellhub/stellguard-go-sdk/proto/stellguard/agent/v1"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	otelcodes "go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const instrumentationName = "github.com/stellhub/stellguard-go-sdk"

type Client struct {
	mu       sync.RWMutex
	conn     *grpc.ClientConn
	workload agentv1.WorkloadCredentialServiceClient
	closed   bool
	options  Options
	metrics  *observability.Recorder
	tracer   trace.Tracer
	ownsConn bool
}

func Dial(ctx context.Context, options Options) (*Client, error) {
	resolved := options.withDefaults()
	target, dialOptions, err := agenttransport.BuildDialOptions(resolved.AgentTarget, resolved.DialOptions)
	if err != nil {
		return nil, err
	}

	dialCtx, cancel := context.WithTimeout(ctx, resolved.Timeout)
	defer cancel()

	conn, err := grpc.DialContext(dialCtx, target, append(dialOptions, grpc.WithBlock())...)
	if err != nil {
		return nil, err
	}

	client := NewWithConn(conn, resolved)
	client.ownsConn = true

	if resolved.FailOnStartup {
		if _, err := client.GetAgentStatus(ctx); err != nil {
			_ = client.Close()
			return nil, err
		}
	}
	return client, nil
}

func NewWithConn(conn *grpc.ClientConn, options Options) *Client {
	resolved := options.withDefaults()
	tracerProvider := resolved.TracerProvider
	if tracerProvider == nil {
		tracerProvider = otel.GetTracerProvider()
	}
	return &Client{
		conn:     conn,
		workload: agentv1.NewWorkloadCredentialServiceClient(conn),
		options:  resolved,
		metrics: observability.NewRecorder(observability.Config{
			Enabled:             boolValue(resolved.MetricsEnabled, true),
			MetricPrefix:        resolved.MetricPrefix,
			AgentTarget:         resolved.AgentTarget,
			InstrumentationName: instrumentationName,
			MeterProvider:       resolved.MeterProvider,
		}),
		tracer: tracerProvider.Tracer(instrumentationName),
	}
}

func (c *Client) Authenticate(ctx context.Context, request AuthRequest) (AuthDecision, error) {
	start := time.Now()
	decision := c.baseDecision(request)
	if c == nil {
		decision = c.applyFailurePolicy(decision, FailureClientClosed, "stellguard client is closed")
		c.recordAuthentication(ctx, request, decision, start, 0)
		return decision, ErrClientClosed
	}
	if err := ctx.Err(); err != nil {
		decision = c.applyFailurePolicy(decision, FailureRequestCanceled, statusMessage(err, "request context is done"))
		c.recordAuthentication(ctx, request, decision, start, 0)
		return decision, err
	}

	if !boolValue(c.options.TracesEnabled, true) {
		return c.authenticate(ctx, request, decision, start)
	}

	ctx, span := c.tracer.Start(ctx, "StellGuard.Authenticate", trace.WithAttributes(
		attribute.String("stellguard.request.protocol", cleanMetricValue(request.Protocol)),
		attribute.String("stellguard.request.method", cleanMetricValue(request.Method)),
		attribute.String("stellguard.request.route", requestRoute(request)),
	))
	defer span.End()

	decision, err := c.authenticate(ctx, request, decision, start)
	span.SetAttributes(
		attribute.Bool("stellguard.allowed", decision.Allowed),
		attribute.String("stellguard.failure_kind", string(decision.FailureKind)),
		attribute.String("stellguard.failure_policy", string(decision.FailurePolicy)),
	)
	if err != nil && isAgentFailure(decision.FailureKind) {
		span.RecordError(err)
		span.SetStatus(otelcodes.Error, err.Error())
	}
	return decision, err
}

func (c *Client) authenticate(ctx context.Context, request AuthRequest, decision AuthDecision, start time.Time) (AuthDecision, error) {
	workload, err := c.workloadClient()
	if err != nil {
		decision = c.applyFailurePolicy(decision, FailureClientClosed, "stellguard client is closed")
		c.recordAuthentication(ctx, request, decision, start, 0)
		return decision, err
	}

	callCtx, cancel := c.callContext(ctx)
	defer cancel()

	includePrivateKey := false
	agentStart := time.Now()
	response, err := workload.FetchWorkloadCredential(callCtx, &agentv1.FetchWorkloadCredentialRequest{
		Audience:          strings.TrimSpace(request.Audience),
		IncludePrivateKey: &includePrivateKey,
	})
	agentDuration := time.Since(agentStart)
	if err != nil {
		decision, returnErr := c.decisionFromError(ctx, decision, err)
		c.recordAuthentication(ctx, request, decision, start, agentDuration)
		return decision, returnErr
	}

	credential := workloadCredentialFromProto(response)
	authCredential := authnCredential(credential)
	if err := authn.ValidateCredential(authCredential); err != nil {
		decision = c.applyFailurePolicy(decision, FailureAgentError, err.Error())
		c.recordAuthentication(ctx, request, decision, start, agentDuration)
		return decision, err
	}

	decision.LocalPrincipal = credential.SPIFFEID
	decision.IdentityID = credential.IdentityID

	if boolValue(c.options.RequirePeerCertificate, true) {
		verified := authn.VerifyRequest(authnRequest(request), authCredential, time.Now())
		if verified.FailureKind != authn.FailureNone {
			decision = c.applyFailurePolicy(decision, failureKindFromAuthn(verified.FailureKind), verified.Reason)
			c.recordAuthentication(ctx, request, decision, start, agentDuration)
			return decision, nil
		}
		decision.Principal = verified.Principal
	} else {
		decision.Principal = credential.SPIFFEID
	}

	decision.Allowed = true
	decision.Bypassed = false
	decision.FailureKind = FailureNone
	decision.FailurePolicy = ""
	decision.Reason = "authenticated"
	c.recordAuthentication(ctx, request, decision, start, agentDuration)
	return decision, nil
}

func (c *Client) FetchWorkloadCredential(ctx context.Context, request WorkloadCredentialRequest) (*WorkloadCredential, error) {
	workload, err := c.workloadClient()
	if err != nil {
		return nil, ErrClientClosed
	}
	callCtx, cancel := c.callContext(ctx)
	defer cancel()

	response, err := workload.FetchWorkloadCredential(callCtx, &agentv1.FetchWorkloadCredentialRequest{
		Audience:          strings.TrimSpace(request.Audience),
		IncludePrivateKey: request.IncludePrivateKey,
	})
	if err != nil {
		return nil, err
	}
	return workloadCredentialFromProto(response), nil
}

func (c *Client) WatchWorkloadCredential(ctx context.Context, request WatchWorkloadCredentialRequest) (*WorkloadCredentialWatcher, error) {
	workload, err := c.workloadClient()
	if err != nil {
		return nil, ErrClientClosed
	}
	callCtx, cancel := c.streamContext(ctx)
	stream, err := workload.WatchWorkloadCredential(callCtx, &agentv1.WatchWorkloadCredentialRequest{
		SendCurrent:       request.SendCurrent,
		Audience:          strings.TrimSpace(request.Audience),
		IncludePrivateKey: request.IncludePrivateKey,
	})
	if err != nil {
		cancel()
		return nil, err
	}
	return &WorkloadCredentialWatcher{
		recv: func() (*WorkloadCredential, error) {
			value, err := stream.Recv()
			if err != nil {
				cancel()
				return nil, err
			}
			return workloadCredentialFromProto(value), nil
		},
		close: func() error {
			cancel()
			return nil
		},
	}, nil
}

func (c *Client) GetTrustBundle(ctx context.Context, request TrustBundleRequest) (*TrustBundle, error) {
	workload, err := c.workloadClient()
	if err != nil {
		return nil, ErrClientClosed
	}
	callCtx, cancel := c.callContext(ctx)
	defer cancel()

	response, err := workload.GetTrustBundle(callCtx, &agentv1.GetTrustBundleRequest{
		TrustDomain: strings.TrimSpace(request.TrustDomain),
	})
	if err != nil {
		return nil, err
	}
	return trustBundleFromProto(response), nil
}

func (c *Client) GetAgentStatus(ctx context.Context) (*AgentStatus, error) {
	workload, err := c.workloadClient()
	if err != nil {
		return nil, ErrClientClosed
	}
	callCtx, cancel := c.callContext(ctx)
	defer cancel()

	response, err := workload.GetAgentStatus(callCtx, &agentv1.GetAgentStatusRequest{})
	if err != nil {
		return nil, err
	}
	return agentStatusFromProto(response), nil
}

func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	conn := c.conn
	ownsConn := c.ownsConn
	c.closed = true
	c.conn = nil
	c.workload = nil
	c.mu.Unlock()

	if !ownsConn || conn == nil {
		return nil
	}
	err := conn.Close()
	return err
}

func (c *Client) MetricsError() error {
	if c == nil || c.metrics == nil {
		return nil
	}
	return c.metrics.Err()
}

func (c *Client) workloadClient() (agentv1.WorkloadCredentialServiceClient, error) {
	if c == nil {
		return nil, ErrClientClosed
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.closed || c.workload == nil {
		return nil, ErrClientClosed
	}
	return c.workload, nil
}

func (c *Client) callContext(ctx context.Context) (context.Context, context.CancelFunc) {
	timeout := DefaultTimeout
	if c != nil && c.options.Timeout > 0 {
		timeout = c.options.Timeout
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	callCtx = c.appendMetadata(callCtx)
	return callCtx, cancel
}

func (c *Client) streamContext(ctx context.Context) (context.Context, context.CancelFunc) {
	callCtx, cancel := context.WithCancel(ctx)
	callCtx = c.appendMetadata(callCtx)
	return callCtx, cancel
}

func (c *Client) appendMetadata(ctx context.Context) context.Context {
	if c != nil && strings.TrimSpace(c.options.AgentToken) != "" {
		return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+strings.TrimSpace(c.options.AgentToken))
	}
	return ctx
}

func (c *Client) baseDecision(request AuthRequest) AuthDecision {
	decision := AuthDecision{
		Allowed:     false,
		FailureKind: FailureInvalidRequest,
		Reason:      "not evaluated",
		Source:      request.Source,
		Metrics:     metricAttributesFromRequest(request),
	}
	if c != nil && !boolValue(c.options.RecordSource, true) {
		decision.Source = RequestSource{}
	}
	return decision
}

func (c *Client) decisionFromError(ctx context.Context, decision AuthDecision, err error) (AuthDecision, error) {
	code := status.Code(err)
	switch code {
	case codes.Canceled:
		if errors.Is(ctx.Err(), context.Canceled) {
			return c.applyFailurePolicy(decision, FailureRequestCanceled, statusMessage(err, "request context is canceled")), err
		}
		return c.applyFailurePolicy(decision, FailureAgentError, statusMessage(err, "agent canceled request")), err
	case codes.Unauthenticated:
		return c.applyFailurePolicy(decision, FailureUnauthenticated, statusMessage(err, "unauthenticated")), nil
	case codes.PermissionDenied:
		return c.applyFailurePolicy(decision, FailureUnauthorized, statusMessage(err, "unauthorized")), nil
	case codes.InvalidArgument:
		return c.applyFailurePolicy(decision, FailureInvalidRequest, statusMessage(err, "invalid request")), err
	case codes.DeadlineExceeded:
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return c.applyFailurePolicy(decision, FailureRequestCanceled, statusMessage(err, "request context deadline exceeded")), err
		}
		return c.applyFailurePolicy(decision, FailureAgentTimeout, statusMessage(err, "agent timeout")), err
	case codes.Unavailable, codes.NotFound, codes.FailedPrecondition:
		return c.applyFailurePolicy(decision, FailureAgentUnavailable, statusMessage(err, "agent unavailable")), err
	default:
		if errors.Is(ctx.Err(), context.Canceled) || errors.Is(err, context.Canceled) {
			return c.applyFailurePolicy(decision, FailureRequestCanceled, statusMessage(err, "request context is canceled")), err
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return c.applyFailurePolicy(decision, FailureRequestCanceled, statusMessage(err, "request context deadline exceeded")), err
		}
		return c.applyFailurePolicy(decision, FailureAgentError, statusMessage(err, "agent error")), err
	}
}

func (c *Client) applyFailurePolicy(decision AuthDecision, failureKind FailureKind, reason string) AuthDecision {
	policy := FailurePolicyDeny
	if isAgentFailure(failureKind) {
		policy = FailurePolicyAllow
		if c != nil {
			policy = c.options.AgentFailurePolicy
		}
	} else if c != nil {
		policy = c.options.AuthFailurePolicy
	}

	decision.FailureKind = failureKind
	decision.FailurePolicy = policy
	decision.Reason = reason
	decision.Allowed = policy == FailurePolicyAllow
	decision.Bypassed = decision.Allowed && failureKind != FailureNone
	return decision
}

func statusMessage(err error, fallback string) string {
	if err == nil {
		return fallback
	}
	if statusValue, ok := status.FromError(err); ok && statusValue.Message() != "" {
		return statusValue.Message()
	}
	if err.Error() != "" {
		return err.Error()
	}
	return fallback
}

func isAgentFailure(kind FailureKind) bool {
	switch kind {
	case FailureAgentUnavailable, FailureAgentTimeout, FailureAgentError:
		return true
	default:
		return false
	}
}
