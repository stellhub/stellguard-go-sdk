package stellguard

import (
	"time"

	"google.golang.org/grpc"
)

const (
	DefaultSocketPath = "/var/run/stellguard/agent.sock"
	DefaultTimeout    = 3 * time.Second
)

type Options struct {
	SocketPath  string
	AgentToken  string
	Timeout     time.Duration
	DialOptions []grpc.DialOption
}

func (o Options) withDefaults() Options {
	if o.SocketPath == "" {
		o.SocketPath = DefaultSocketPath
	}
	if o.Timeout <= 0 {
		o.Timeout = DefaultTimeout
	}
	return o
}
