package hip

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// defaultRegistryRootKeyPEM is the canonical registry root public key per
// PROTOCOL.md §10.8. SDK releases ship with this pinned; rotation will be
// announced 90 days in advance with overlap windows so older SDK versions
// continue to verify against either the old or new key.
const defaultRegistryRootKeyPEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAjLot1q9kopqfW3KAZyPcErPNwnoDRp56VPslKSNHqnA=
-----END PUBLIC KEY-----
`

// DefaultRegistryRootKey is the parsed Ed25519 public key for the canonical
// registry. New() pins this on every Client unless WithRegistryRootKey
// overrides it (dev / federation testing per PROTOCOL.md §10.8).
var DefaultRegistryRootKey = mustParseDefaultRegistryRootKey()

func mustParseDefaultRegistryRootKey() ed25519.PublicKey {
	block, _ := pem.Decode([]byte(defaultRegistryRootKeyPEM))
	if block == nil {
		panic("hip: defaultRegistryRootKeyPEM is not valid PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(fmt.Sprintf("hip: parse defaultRegistryRootKeyPEM: %v", err))
	}
	edKey, ok := pub.(ed25519.PublicKey)
	if !ok {
		panic(fmt.Sprintf("hip: defaultRegistryRootKey is not Ed25519, got %T", pub))
	}
	return edKey
}
