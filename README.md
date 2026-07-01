# StellGuard Go SDK

StellGuard Go SDK is the framework-neutral Go client for the StellGuard zero-trust identity platform. It connects to `stellguard-agent` over gRPC through a Unix Domain Socket and provides a compact API for fetching workload certificates, trust bundles, and local mTLS identity material.

The SDK is designed to become the Go identity integration layer for `stellar` and other Stell runtime frameworks while keeping the core package independent from application-framework assumptions.

## Positioning

- `stellguard-service` is the zero-trust identity control plane.
- `stellguard-agent` runs beside workloads and mediates node/workload identity.
- `stellguard-go-sdk` talks only to the local agent through gRPC over Unix Domain Socket.
- `stellar` can later wrap this SDK with framework conventions and runtime lifecycle management.

## Capabilities

- Dial `stellguard-agent` through Unix Domain Socket transport.
- Fetch SPIFFE-style workload certificates.
- Fetch the active trust bundle from the local agent.
- Attach an optional agent token as gRPC metadata.
- Keep the public API framework-neutral for future `stellar` integration.

## Quick Start

```go
package main

import (
	"context"
	"fmt"
	"time"

	stellguard "github.com/stellhub/stellguard-go-sdk"
)

func main() {
	ctx := context.Background()

	client, err := stellguard.Dial(ctx, stellguard.Options{
		SocketPath: "/var/run/stellguard/agent.sock",
		Timeout:    3 * time.Second,
	})
	if err != nil {
		panic(err)
	}
	defer client.Close()

	bundle, err := client.FetchWorkloadCertificate(ctx, stellguard.CredentialRequest{
		SPIFFEID: "spiffe://stell.local/workload/api",
		DNSNames: []string{"api.local"},
		TTL:      15 * time.Minute,
	})
	if err != nil {
		panic(err)
	}

	fmt.Println(bundle.KeyID)
}
```

## Development

Generate protobuf code:

```bash
protoc --go_out=. --go-grpc_out=. --go_opt=paths=source_relative --go-grpc_opt=paths=source_relative proto/stellguard/agent/v1/agent.proto
```

Run tests:

```bash
go test ./...
```

## Contract

The initial gRPC contract is stored in `proto/stellguard/agent/v1/agent.proto`. It is intentionally agent-facing rather than service-facing: applications should request workload identity material from the local node agent instead of calling the central control plane directly.
