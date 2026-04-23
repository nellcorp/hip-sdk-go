# hip-sdk-go

Go SDK for platforms integrating with the [Human Identity Protocol](https://github.com/nellcorp/hip).

## Install

```bash
go get github.com/nellcorp/hip-sdk-go
```

## Usage

```go
package main

import (
    "context"
    "fmt"
    "time"

    hip "github.com/nellcorp/hip-sdk-go"
)

func main() {
    // Key resolver fetches provider public keys from the registry
    // with 24h caching and last-known-good fallback.
    resolver := hip.NewRegistryKeyResolver(
        "https://registry.hip.dev",
        24*time.Hour,
    )

    // Create a client with your platform API key (hip_sk_…).
    client := hip.New(
        "hip_sk_your_api_key",
        hip.WithKeyResolver(resolver),
    )

    // Verify a human identity. The provider URL is auto-discovered
    // from the subject ID (abc123@provider.example.com → provider.example.com).
    resp, err := client.Verify(context.Background(), hip.VerifyRequest{
        SubjectID:    "abc123@provider.example.com",
        Purpose:      "account_creation",
        MinimumScore: 60,
    })
    if err != nil {
        panic(err)
    }

    fmt.Printf("Status: %s, Score: %d\n", resp.Status, resp.Score)
}
```

## Features

- **Automatic JWS signature verification** using Ed25519 public keys from the registry
- **Nonce generation** — cryptographically random nonce auto-generated per request
- **Request ID generation** — UUID v4 auto-generated if not provided
- **Registry key resolver** with TTL-based caching and last-known-good fallback
- **Nonce verification** — ensures response nonce matches request
- **Auto-discovery** — provider URL derived from subject ID (`{id}@{provider}`)
- Zero external dependencies beyond `github.com/google/uuid`

## Custom Key Resolver

Implement `hip.KeyResolver` to use your own key management:

```go
type KeyResolver interface {
    ResolvePublicKey(ctx context.Context, providerID string) (ed25519.PublicKey, error)
}
```
