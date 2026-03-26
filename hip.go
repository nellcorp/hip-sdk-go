// Package hip provides a Go SDK for platforms integrating with the
// Human Identity Protocol. It handles verification requests, JWS
// signature verification, nonce generation, and provider key management
// via the public registry.
package hip

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// VerifyRequest is sent by platforms to verify a human.
type VerifyRequest struct {
	SubjectID    string `json:"subject_id"`
	RequestID    string `json:"request_id"`
	MinimumScore int    `json:"minimum_score"`
	Purpose      string `json:"purpose"`
	Nonce        string `json:"nonce"`
}

// VerifyResponse is the provider's signed response.
type VerifyResponse struct {
	RequestID              string          `json:"request_id"`
	SubjectID              string          `json:"subject_id"`
	Status                 string          `json:"status"`
	Score                  int             `json:"score"`
	ScoreState             string          `json:"score_state"`
	ScoreComponents        ScoreComponents `json:"score_components"`
	CertificateFingerprint string          `json:"certificate_fingerprint"`
	IssuedAt               time.Time       `json:"issued_at"`
	ExpiresAt              time.Time       `json:"expires_at"`
	Nonce                  string          `json:"nonce"`
	Signature              string          `json:"signature,omitempty"`
}

// ScoreComponents provides detail about the score.
type ScoreComponents struct {
	VerificationAgeDays int      `json:"verification_age_days"`
	RecentEvents        []string `json:"recent_events"`
	ActiveFlags         []string `json:"active_flags"`
}

// KeyResolver fetches a provider's Ed25519 public key (PEM-encoded).
// The SDK ships with RegistryKeyResolver for production use, but
// callers can provide their own for testing or custom key management.
type KeyResolver interface {
	ResolvePublicKey(ctx context.Context, providerID string) (ed25519.PublicKey, error)
}

// Client is a HIP SDK client for verifying human identities.
// Safe for concurrent use.
type Client struct {
	httpClient      *http.Client
	keyResolver     KeyResolver
	apiKey          string
	jwtSecret       string
	providerBaseURL string // override for testing/local dev — skips URL derivation from subject ID
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient sets a custom http.Client.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) { c.httpClient = hc }
}

// WithKeyResolver sets a custom key resolver.
func WithKeyResolver(kr KeyResolver) Option {
	return func(c *Client) { c.keyResolver = kr }
}

// WithProviderURL overrides the auto-discovered provider URL.
// Useful for testing or when the provider uses a non-standard URL.
// The SDK will POST to {providerURL}/verify instead of deriving
// the URL from the subject ID.
func WithProviderURL(url string) Option {
	return func(c *Client) { c.providerBaseURL = url }
}

// New creates a HIP SDK client. apiKey and jwtSecret are the credentials
// returned when the platform registered with a HIP provider.
func New(apiKey, jwtSecret string, opts ...Option) *Client {
	c := &Client{
		httpClient: &http.Client{Timeout: 10 * time.Second},
		apiKey:     apiKey,
		jwtSecret:  jwtSecret,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Verify sends a verification request to the subject's provider and verifies
// the response signature. The provider URL is derived from the subject ID
// (e.g. "abc123@provider.example.com" → "https://provider.example.com/.well-known/identity/verify").
//
// A nonce and request ID are generated automatically if not set.
func (c *Client) Verify(ctx context.Context, req VerifyRequest) (*VerifyResponse, error) {
	if req.SubjectID == "" {
		return nil, fmt.Errorf("hip: subject_id is required")
	}

	providerID, err := extractProviderFromSubject(req.SubjectID)
	if err != nil {
		return nil, err
	}

	var verifyURL string
	if c.providerBaseURL != "" {
		verifyURL = c.providerBaseURL + "/verify"
	} else {
		verifyURL = "https://" + providerID + "/.well-known/identity/verify"
	}

	// Auto-generate nonce and request ID if not provided.
	if req.Nonce == "" {
		req.Nonce = generateNonce()
	}
	if req.RequestID == "" {
		req.RequestID = uuid.New().String()
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("hip: marshaling request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, verifyURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("hip: creating request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.jwtSecret)
	httpReq.Header.Set("X-API-Key", c.apiKey)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("hip: sending request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB max
	if err != nil {
		return nil, fmt.Errorf("hip: reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hip: provider returned %d: %s", resp.StatusCode, string(respBody))
	}

	var verifyResp VerifyResponse
	if err := json.Unmarshal(respBody, &verifyResp); err != nil {
		return nil, fmt.Errorf("hip: decoding response: %w", err)
	}

	// Verify nonce matches.
	if verifyResp.Nonce != req.Nonce {
		return nil, fmt.Errorf("hip: nonce mismatch: sent %q, got %q", req.Nonce, verifyResp.Nonce)
	}

	// Verify JWS signature if a key resolver is configured.
	if c.keyResolver != nil && verifyResp.Signature != "" {
		pubKey, keyErr := c.keyResolver.ResolvePublicKey(ctx, providerID)
		if keyErr != nil {
			return nil, fmt.Errorf("hip: resolving provider key: %w", keyErr)
		}

		// Verify the JWS token. The signature field contains the full
		// JWS compact serialization; the payload should match the
		// response without the signature field.
		if _, jwsErr := verifyJWS(pubKey, verifyResp.Signature); jwsErr != nil {
			return nil, fmt.Errorf("hip: invalid signature: %w", jwsErr)
		}
	}

	return &verifyResp, nil
}

// generateNonce creates a cryptographically random 32-byte nonce encoded as base64url.
func generateNonce() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("hip: crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// extractProviderFromSubject parses the provider domain from a subject ID.
// e.g. "abc123@provider.example.com" → "provider.example.com"
func extractProviderFromSubject(subjectID string) (string, error) {
	idx := strings.LastIndex(subjectID, "@")
	if idx < 0 || idx == len(subjectID)-1 {
		return "", fmt.Errorf("hip: invalid subject_id format, expected {id}@{provider}: %q", subjectID)
	}
	return subjectID[idx+1:], nil
}

// --- JWS verification (self-contained, no external deps) ---

var jwsHeader = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"JWT"}`))

func verifyJWS(publicKey ed25519.PublicKey, token string) ([]byte, error) {
	parts := strings.SplitN(token, ".", 4)
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed JWS: expected 3 parts, got %d", len(parts))
	}

	signingInput := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decoding signature: %w", err)
	}

	if !ed25519.Verify(publicKey, []byte(signingInput), sig) {
		return nil, fmt.Errorf("invalid signature")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decoding payload: %w", err)
	}

	return payload, nil
}

// ParsePEMPublicKey parses a PEM-encoded Ed25519 public key.
func ParsePEMPublicKey(pemData string) (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("hip: no PEM block found")
	}
	// Ed25519 public key is 32 bytes; PKIX wrapping adds overhead.
	// Try raw key first (32 bytes), then PKIX.
	if len(block.Bytes) == ed25519.PublicKeySize {
		return ed25519.PublicKey(block.Bytes), nil
	}
	// PKIX-encoded Ed25519 public key: 12-byte prefix + 32-byte key.
	if len(block.Bytes) == 44 {
		return ed25519.PublicKey(block.Bytes[12:]), nil
	}
	return nil, fmt.Errorf("hip: unexpected key size %d", len(block.Bytes))
}

// --- Registry-backed key resolver ---

// RegistryKeyResolver resolves provider public keys from the HIP registry
// with in-memory caching and last-known-good fallback.
type RegistryKeyResolver struct {
	registryURL string
	httpClient  *http.Client
	ttl         time.Duration

	mu    sync.RWMutex
	cache map[string]*cachedKey
}

type cachedKey struct {
	key       ed25519.PublicKey
	fetchedAt time.Time
}

// NewRegistryKeyResolver creates a key resolver backed by the HIP registry.
func NewRegistryKeyResolver(registryURL string, ttl time.Duration, httpClient ...*http.Client) *RegistryKeyResolver {
	hc := &http.Client{Timeout: 10 * time.Second}
	if len(httpClient) > 0 && httpClient[0] != nil {
		hc = httpClient[0]
	}
	return &RegistryKeyResolver{
		registryURL: registryURL,
		httpClient:  hc,
		ttl:         ttl,
		cache:       make(map[string]*cachedKey),
	}
}

// ResolvePublicKey fetches the provider's public key from the registry,
// with caching and last-known-good fallback.
func (r *RegistryKeyResolver) ResolvePublicKey(ctx context.Context, providerID string) (ed25519.PublicKey, error) {
	r.mu.RLock()
	cached := r.cache[providerID]
	r.mu.RUnlock()

	if cached != nil && time.Since(cached.fetchedAt) < r.ttl {
		return cached.key, nil
	}

	// Fetch from registry.
	url := fmt.Sprintf("%s/providers/%s/certificate", r.registryURL, providerID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		if cached != nil {
			return cached.key, nil
		}
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		if cached != nil {
			return cached.key, nil
		}
		return nil, fmt.Errorf("hip: registry request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		if cached != nil {
			return cached.key, nil
		}
		return nil, fmt.Errorf("hip: registry returned %d for %s", resp.StatusCode, providerID)
	}

	var certResp struct {
		PublicKey string `json:"public_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&certResp); err != nil {
		if cached != nil {
			return cached.key, nil
		}
		return nil, fmt.Errorf("hip: decoding registry response: %w", err)
	}

	pubKey, err := ParsePEMPublicKey(certResp.PublicKey)
	if err != nil {
		if cached != nil {
			return cached.key, nil
		}
		return nil, err
	}

	r.mu.Lock()
	r.cache[providerID] = &cachedKey{key: pubKey, fetchedAt: time.Now()}
	r.mu.Unlock()

	return pubKey, nil
}
