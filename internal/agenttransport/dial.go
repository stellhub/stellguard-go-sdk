package agenttransport

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func BuildDialOptions(agentTarget string, extraOptions []grpc.DialOption) (string, []grpc.DialOption, error) {
	target := strings.TrimSpace(agentTarget)
	dialOptions := append([]grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}, extraOptions...)

	parsed, err := url.Parse(target)
	if err != nil || parsed.Scheme == "" {
		return "", nil, fmt.Errorf("agent target must use unix:// scheme")
	}
	if parsed.Scheme != "unix" {
		return "", nil, fmt.Errorf("unsupported agent target scheme %q; workload API must use unix://", parsed.Scheme)
	}

	address := parsed.Path
	if address == "" {
		address = parsed.Host
	}
	if address == "" {
		return "", nil, fmt.Errorf("unix agent target requires a socket path")
	}

	dialOptions = append(dialOptions, grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, "unix", address)
	}))
	return target, dialOptions, nil
}
