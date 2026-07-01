package stellguard

import (
	"context"
	"strings"

	agentv1 "github.com/stellhub/stellguard-go-sdk/proto/stellguard/agent/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

type Client struct {
	conn     *grpc.ClientConn
	agent    agentv1.StellGuardAgentClient
	options  Options
	ownsConn bool
}

func Dial(ctx context.Context, options Options) (*Client, error) {
	resolved := options.withDefaults()
	dialOptions := append([]grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}, resolved.DialOptions...)

	target := "unix://" + resolved.SocketPath
	dialCtx, cancel := context.WithTimeout(ctx, resolved.Timeout)
	defer cancel()

	conn, err := grpc.DialContext(dialCtx, target, append(dialOptions, grpc.WithBlock())...)
	if err != nil {
		return nil, err
	}

	return &Client{
		conn:     conn,
		agent:    agentv1.NewStellGuardAgentClient(conn),
		options:  resolved,
		ownsConn: true,
	}, nil
}

func NewWithConn(conn *grpc.ClientConn, options Options) *Client {
	resolved := options.withDefaults()
	return &Client{
		conn:     conn,
		agent:    agentv1.NewStellGuardAgentClient(conn),
		options:  resolved,
		ownsConn: false,
	}
}

func (c *Client) FetchWorkloadCertificate(ctx context.Context, request CredentialRequest) (*CredentialBundle, error) {
	protoRequest, err := request.toProto()
	if err != nil {
		return nil, err
	}

	callCtx, cancel := c.callContext(ctx)
	defer cancel()

	response, err := c.agent.FetchWorkloadCertificate(callCtx, protoRequest)
	if err != nil {
		return nil, err
	}
	return credentialBundleFromProto(response), nil
}

func (c *Client) FetchTrustBundle(ctx context.Context, trustDomain string) (*CredentialBundle, error) {
	callCtx, cancel := c.callContext(ctx)
	defer cancel()

	response, err := c.agent.FetchTrustBundle(callCtx, &agentv1.FetchTrustBundleRequest{
		TrustDomain: strings.TrimSpace(trustDomain),
	})
	if err != nil {
		return nil, err
	}
	return credentialBundleFromTrustBundle(response), nil
}

func (c *Client) Close() error {
	if c == nil || !c.ownsConn || c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

func (c *Client) callContext(ctx context.Context) (context.Context, context.CancelFunc) {
	timeout := c.options.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	if c.options.AgentToken != "" {
		callCtx = metadata.AppendToOutgoingContext(callCtx, "authorization", "Bearer "+strings.TrimSpace(c.options.AgentToken))
	}
	return callCtx, cancel
}
