package observability

import (
	"context"
	"errors"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

type Config struct {
	Enabled             bool
	MetricPrefix        string
	AgentTarget         string
	InstrumentationName string
	MeterProvider       metric.MeterProvider
}

type Request struct {
	Protocol    string
	Method      string
	Route       string
	Operation   string
	ServiceName string
	SourceZone  string
}

type Decision struct {
	Allowed       bool
	Bypassed      bool
	FailureKind   string
	FailurePolicy string
	AgentFailure  bool
}

type Recorder struct {
	enabled       bool
	err           error
	agentTarget   string
	requests      metric.Int64Counter
	decisions     metric.Int64Counter
	denied        metric.Int64Counter
	bypassed      metric.Int64Counter
	agentFailures metric.Int64Counter
	duration      metric.Float64Histogram
	agentDuration metric.Float64Histogram
}

func NewRecorder(config Config) *Recorder {
	if !config.Enabled {
		return &Recorder{}
	}
	provider := config.MeterProvider
	if provider == nil {
		provider = otel.GetMeterProvider()
	}
	instrumentationName := strings.TrimSpace(config.InstrumentationName)
	if instrumentationName == "" {
		instrumentationName = "github.com/stellhub/stellguard-go-sdk"
	}
	meter := provider.Meter(instrumentationName)
	prefix := strings.TrimSuffix(config.MetricPrefix, ".")
	if prefix == "" {
		prefix = "stellguard.auth"
	}

	var instrumentErr error
	requests, err := meter.Int64Counter(prefix + ".requests")
	instrumentErr = errors.Join(instrumentErr, err)
	decisions, err := meter.Int64Counter(prefix + ".decisions")
	instrumentErr = errors.Join(instrumentErr, err)
	denied, err := meter.Int64Counter(prefix + ".denied")
	instrumentErr = errors.Join(instrumentErr, err)
	bypassed, err := meter.Int64Counter(prefix + ".bypassed")
	instrumentErr = errors.Join(instrumentErr, err)
	agentFailures, err := meter.Int64Counter(prefix + ".agent.failures")
	instrumentErr = errors.Join(instrumentErr, err)
	duration, err := meter.Float64Histogram(prefix+".duration", metric.WithUnit("s"))
	instrumentErr = errors.Join(instrumentErr, err)
	agentDuration, err := meter.Float64Histogram(prefix+".agent.duration", metric.WithUnit("s"))
	instrumentErr = errors.Join(instrumentErr, err)
	if instrumentErr != nil {
		return &Recorder{err: instrumentErr}
	}

	return &Recorder{
		enabled:       true,
		agentTarget:   config.AgentTarget,
		requests:      requests,
		decisions:     decisions,
		denied:        denied,
		bypassed:      bypassed,
		agentFailures: agentFailures,
		duration:      duration,
		agentDuration: agentDuration,
	}
}

func (r *Recorder) Err() error {
	if r == nil {
		return nil
	}
	return r.err
}

func (r *Recorder) Record(ctx context.Context, request Request, decision Decision, start time.Time, agentDuration time.Duration) {
	if r == nil || !r.enabled {
		return
	}
	attrs := metricAttributes(request, decision, r.agentTarget)
	options := metric.WithAttributes(attrs...)
	r.requests.Add(ctx, 1, options)
	r.decisions.Add(ctx, 1, options)
	if !decision.Allowed {
		r.denied.Add(ctx, 1, options)
	}
	if decision.Bypassed {
		r.bypassed.Add(ctx, 1, options)
	}
	if decision.AgentFailure {
		r.agentFailures.Add(ctx, 1, options)
	}
	r.duration.Record(ctx, time.Since(start).Seconds(), options)
	if agentDuration > 0 {
		r.agentDuration.Record(ctx, agentDuration.Seconds(), options)
	}
}

func RequestAttributes(request Request) map[string]string {
	return map[string]string{
		"protocol":     cleanMetricValue(request.Protocol),
		"method":       cleanMetricValue(request.Method),
		"route":        requestRoute(request),
		"service_name": cleanMetricValue(request.ServiceName),
		"source_zone":  cleanMetricValue(request.SourceZone),
	}
}

func metricAttributes(request Request, decision Decision, target string) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.String("protocol", cleanMetricValue(request.Protocol)),
		attribute.String("method", cleanMetricValue(request.Method)),
		attribute.String("route", requestRoute(request)),
		attribute.String("decision", decisionValue(decision.Allowed)),
		attribute.String("failure_kind", cleanMetricValue(decision.FailureKind)),
		attribute.String("failure_policy", failurePolicyMetricValue(decision.FailurePolicy)),
		attribute.String("agent_target_type", agentTargetType(target)),
		attribute.String("service_name", cleanMetricValue(request.ServiceName)),
		attribute.String("source_zone", cleanMetricValue(request.SourceZone)),
	}
}

func requestRoute(request Request) string {
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

func decisionValue(allowed bool) string {
	if allowed {
		return "allow"
	}
	return "deny"
}

func failurePolicyMetricValue(policy string) string {
	if policy == "" {
		return "none"
	}
	return policy
}

func agentTargetType(target string) string {
	if strings.HasPrefix(strings.TrimSpace(target), "unix://") {
		return "unix"
	}
	if strings.TrimSpace(target) == "" {
		return "unix"
	}
	return "network"
}
