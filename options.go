package stellguard

import (
	"time"

	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
)

const (
	DefaultAgentTarget  = "unix:///var/run/stellguard/agent.sock"
	DefaultSocketPath   = "/var/run/stellguard/agent.sock"
	DefaultTimeout      = 300 * time.Millisecond
	DefaultMetricPrefix = "stellguard.auth"
)

type Options struct {
	AgentTarget            string
	SocketPath             string
	AgentToken             string
	Timeout                time.Duration
	FailOnStartup          bool
	AuthFailurePolicy      FailurePolicy
	AgentFailurePolicy     FailurePolicy
	RequirePeerCertificate *bool
	RecordSource           *bool
	MetricsEnabled         *bool
	TracesEnabled          *bool
	MetricPrefix           string
	MeterProvider          metric.MeterProvider
	TracerProvider         trace.TracerProvider
	DialOptions            []grpc.DialOption
}

func (o Options) withDefaults() Options {
	if o.AgentTarget == "" {
		if o.SocketPath != "" {
			o.AgentTarget = "unix://" + o.SocketPath
		} else {
			o.AgentTarget = DefaultAgentTarget
		}
	}
	if o.SocketPath == "" {
		o.SocketPath = DefaultSocketPath
	}
	if o.Timeout <= 0 {
		o.Timeout = DefaultTimeout
	}
	o.AuthFailurePolicy = normalizePolicy(o.AuthFailurePolicy, FailurePolicyDeny)
	o.AgentFailurePolicy = normalizePolicy(o.AgentFailurePolicy, FailurePolicyAllow)
	if o.RequirePeerCertificate == nil {
		o.RequirePeerCertificate = Bool(true)
	}
	if o.RecordSource == nil {
		o.RecordSource = Bool(true)
	}
	if o.MetricsEnabled == nil {
		o.MetricsEnabled = Bool(true)
	}
	if o.TracesEnabled == nil {
		o.TracesEnabled = Bool(true)
	}
	if o.MetricPrefix == "" {
		o.MetricPrefix = DefaultMetricPrefix
	}
	return o
}

func normalizePolicy(value FailurePolicy, fallback FailurePolicy) FailurePolicy {
	switch value {
	case FailurePolicyAllow, FailurePolicyDeny:
		return value
	default:
		return fallback
	}
}

func boolValue(value *bool, fallback bool) bool {
	if value == nil {
		return fallback
	}
	return *value
}
