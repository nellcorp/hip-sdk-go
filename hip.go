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
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// VerifyRequest is sent by platforms to verify a human.
type VerifyRequest struct {
	SubjectID    string `json:"subject_id"`
	MinimumScore int    `json:"minimum_score,omitempty"`
	Purpose      string `json:"purpose,omitempty"`
	Nonce        string `json:"nonce"`
}

// VerifyResponse is the provider's signed response.
type VerifyResponse struct {
	SubjectID              string          `json:"subject_id"`
	Status                 string          `json:"status"`
	Score                  int             `json:"score"`
	ScoreState             string          `json:"score_state"`
	ScoreComponents        ScoreComponents `json:"score_components"`
	CertificateFingerprint string          `json:"certificate_fingerprint"`
	IssuedAt               time.Time       `json:"issued_at"`
	ExpiresAt              time.Time       `json:"expires_at"`
	Nonce                  string          `json:"nonce"`
}

// VerifyResult wraps a VerifyResponse with metadata about the verification.
type VerifyResult struct {
	VerifyResponse
	// RegistryStale is true when the provider's public key was resolved from
	// a stale cache because the registry was unreachable.
	RegistryStale bool
}

// ScoreComponents provides detail about the score.
type ScoreComponents struct {
	VerificationAgeDays int      `json:"verification_age_days"`
	RecentEvents        []string `json:"recent_events"`
	ActiveFlags         []string `json:"active_flags"`
}

// ExchangeRequest is sent by platforms to exchange a signup code for subject_id + verification.
type ExchangeRequest struct {
	SignupCode string `json:"signup_code"`
	Nonce      string `json:"nonce"`
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

// New creates a HIP SDK client. apiKey is the `hip_sk_…` secret issued by the
// provider for the platform. The SDK sends it as a Bearer token on every
// request; the provider derives the platform from the key.
func New(apiKey string, opts ...Option) *Client {
	c := &Client{
		httpClient: &http.Client{Timeout: 10 * time.Second},
		apiKey:     apiKey,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Verify sends a verification request to the subject's provider and verifies
// the response signature. The provider URL is derived from the subject ID
// (e.g. "abc123@provider.example.com" → "https://provider.example.com/.well-known/hip/verify").
//
// The response is a JWS compact serialization (RFC 7515) with Content-Type
// application/jose. The SDK decodes the JWS, verifies the Ed25519 signature
// against the provider's public key from the registry, and returns the decoded payload.
//
// A nonce and request ID are generated automatically if not set.
func (c *Client) Verify(ctx context.Context, req VerifyRequest) (*VerifyResult, error) {
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
		verifyURL = "https://" + providerID + "/.well-known/hip/verify"
	}

	// Auto-generate nonce if not provided.
	if req.Nonce == "" {
		req.Nonce = generateNonce()
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
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)

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

	// Response body is a JWS compact serialization (header.payload.signature).
	jwsToken := strings.TrimSpace(string(respBody))

	result := &VerifyResult{}

	// Verify JWS signature if a key resolver is configured.
	if c.keyResolver != nil {
		pubKey, registryStale, keyErr := c.resolveKeyWithStaleFlag(ctx, providerID)
		if keyErr != nil {
			return nil, fmt.Errorf("hip: resolving provider key: %w", keyErr)
		}
		result.RegistryStale = registryStale

		payload, jwsErr := verifyJWS(pubKey, jwsToken)
		if jwsErr != nil {
			return nil, fmt.Errorf("hip: invalid signature: %w", jwsErr)
		}

		if err := json.Unmarshal(payload, &result.VerifyResponse); err != nil {
			return nil, fmt.Errorf("hip: decoding JWS payload: %w", err)
		}
	} else {
		// No key resolver — decode payload without signature verification.
		parts := strings.SplitN(jwsToken, ".", 4)
		if len(parts) != 3 {
			return nil, fmt.Errorf("hip: malformed JWS: expected 3 parts, got %d", len(parts))
		}
		payload, decErr := base64.RawURLEncoding.DecodeString(parts[1])
		if decErr != nil {
			return nil, fmt.Errorf("hip: decoding JWS payload: %w", decErr)
		}
		if err := json.Unmarshal(payload, &result.VerifyResponse); err != nil {
			return nil, fmt.Errorf("hip: decoding response: %w", err)
		}
	}

	// Verify nonce matches.
	if result.Nonce != req.Nonce {
		return nil, fmt.Errorf("hip: nonce mismatch: sent %q, got %q", req.Nonce, result.Nonce)
	}

	// Verify attestation has not expired.
	if time.Now().After(result.ExpiresAt) {
		return nil, fmt.Errorf("hip: attestation expired at %v", result.ExpiresAt)
	}

	return result, nil
}

// ExchangeSignupCode exchanges a user's signup code for their subject_id and verification.
// This is used during platform signup when the user provides their HIP signup code.
// The signup code is single-use and expires after 1 hour.
//
// Unlike Verify, this method requires the provider URL to be set via WithProviderURL
// since the signup code does not contain provider information.
//
// A nonce and request ID are generated automatically if not set.
func (c *Client) ExchangeSignupCode(ctx context.Context, req ExchangeRequest) (*VerifyResult, error) {
	if req.SignupCode == "" {
		return nil, fmt.Errorf("hip: signup_code is required")
	}

	if c.providerBaseURL == "" {
		return nil, fmt.Errorf("hip: provider URL is required for exchange (use WithProviderURL)")
	}

	exchangeURL := c.providerBaseURL + "/exchange"

	// Auto-generate nonce if not provided.
	if req.Nonce == "" {
		req.Nonce = generateNonce()
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("hip: marshaling request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, exchangeURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("hip: creating request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)

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

	// Response body is a JWS compact serialization.
	jwsToken := strings.TrimSpace(string(respBody))

	result := &VerifyResult{}

	// Decode payload without signature verification for exchange (no providerID).
	parts := strings.SplitN(jwsToken, ".", 4)
	if len(parts) != 3 {
		return nil, fmt.Errorf("hip: malformed JWS: expected 3 parts, got %d", len(parts))
	}
	payload, decErr := base64.RawURLEncoding.DecodeString(parts[1])
	if decErr != nil {
		return nil, fmt.Errorf("hip: decoding JWS payload: %w", decErr)
	}
	if err := json.Unmarshal(payload, &result.VerifyResponse); err != nil {
		return nil, fmt.Errorf("hip: decoding response: %w", err)
	}

	// Verify nonce matches.
	if result.Nonce != req.Nonce {
		return nil, fmt.Errorf("hip: nonce mismatch: sent %q, got %q", req.Nonce, result.Nonce)
	}

	// Verify attestation has not expired.
	if time.Now().After(result.ExpiresAt) {
		return nil, fmt.Errorf("hip: attestation expired at %v", result.ExpiresAt)
	}

	return result, nil
}

// OAuthStartOptions configures StartOAuth.
type OAuthStartOptions struct {
	// ProviderDomain is the HIP provider's domain (e.g. "humanidentity.io").
	ProviderDomain string
	// ClientID is the platform's canonical_platform_id.
	ClientID string
	// RedirectURI must be a URI registered on the platform.
	RedirectURI string
	// State is an opaque CSRF token echoed back on the redirect.
	State string
}

// OAuthFlow is returned by StartOAuth. AuthorizeURL is where to redirect the
// user's browser. Verifier is the PKCE code_verifier — caller MUST retain it
// (typically in session storage) until CompleteOAuth.
type OAuthFlow struct {
	AuthorizeURL string
	Verifier     string
}

// OAuthTokenResponse is returned from CompleteOAuth.
type OAuthTokenResponse struct {
	SubjectID   string `json:"subject_id"`
	Status      string `json:"status"`
	Score       int    `json:"score"`
	ScoreState  string `json:"score_state"`
	Attestation string `json:"attestation"` // JWS compact
	IssuedAt    string `json:"issued_at"`
	ExpiresAt   string `json:"expires_at"`
}

// StartOAuth generates a PKCE verifier/challenge pair and returns the
// authorize URL to send the user to.
//
//	flow, err := c.StartOAuth(hip.OAuthStartOptions{
//	    ProviderDomain: "humanidentity.io",
//	    ClientID:       "my-platform.example.com",
//	    RedirectURI:    "https://my-platform.example.com/oauth/callback",
//	    State:          "csrf-token",
//	})
//	// save flow.Verifier in the user's session
//	// redirect to flow.AuthorizeURL
func (c *Client) StartOAuth(opts OAuthStartOptions) (*OAuthFlow, error) {
	if opts.ClientID == "" {
		return nil, fmt.Errorf("hip: ClientID is required")
	}
	if opts.RedirectURI == "" {
		return nil, fmt.Errorf("hip: RedirectURI is required")
	}
	base := c.providerBaseURL
	if base == "" {
		if opts.ProviderDomain == "" {
			return nil, fmt.Errorf("hip: ProviderDomain is required (or configure the client with WithProviderURL)")
		}
		base = "https://" + opts.ProviderDomain
	}
	// `base` points at the provider root; /oauth/authorize lives alongside /.well-known/hip.
	// If the caller supplied a /.well-known/hip URL via WithProviderURL, strip it.
	base = strings.TrimSuffix(base, "/.well-known/hip")
	base = strings.TrimSuffix(base, "/")

	verifier, err := generateCodeVerifier()
	if err != nil {
		return nil, fmt.Errorf("hip: generating code_verifier: %w", err)
	}
	challenge := codeChallenge(verifier)

	q := url.Values{}
	q.Set("client_id", opts.ClientID)
	q.Set("redirect_uri", opts.RedirectURI)
	q.Set("response_type", "code")
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	if opts.State != "" {
		q.Set("state", opts.State)
	}

	return &OAuthFlow{
		AuthorizeURL: base + "/oauth/authorize?" + q.Encode(),
		Verifier:     verifier,
	}, nil
}

// CompleteOAuth exchanges an authorization code + PKCE verifier for a
// verification attestation. The platform is authenticated by client_id + PKCE;
// no Bearer header is sent on this request.
//
//	resp, err := c.CompleteOAuth(ctx, code, verifier, hip.CompleteOAuthOptions{
//	    ProviderDomain: "humanidentity.io",
//	    ClientID:       "my-platform.example.com",
//	})
func (c *Client) CompleteOAuth(ctx context.Context, code, verifier string, opts CompleteOAuthOptions) (*OAuthTokenResponse, error) {
	if code == "" {
		return nil, fmt.Errorf("hip: code is required")
	}
	if verifier == "" {
		return nil, fmt.Errorf("hip: verifier is required")
	}
	if opts.ClientID == "" {
		return nil, fmt.Errorf("hip: ClientID is required")
	}
	base := c.providerBaseURL
	if base == "" {
		if opts.ProviderDomain == "" {
			return nil, fmt.Errorf("hip: ProviderDomain is required")
		}
		base = "https://" + opts.ProviderDomain
	}
	base = strings.TrimSuffix(base, "/.well-known/hip")
	base = strings.TrimSuffix(base, "/")

	body, err := json.Marshal(map[string]string{
		"grant_type":    "authorization_code",
		"code":          code,
		"client_id":     opts.ClientID,
		"code_verifier": verifier,
	})
	if err != nil {
		return nil, fmt.Errorf("hip: marshaling request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/oauth/token", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("hip: creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// NOTE: /oauth/token does not accept an Authorization header. PKCE +
	// client_id are the platform authentication.

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("hip: sending request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("hip: reading response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hip: provider returned %d: %s", resp.StatusCode, string(respBody))
	}

	var out OAuthTokenResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("hip: decoding response: %w", err)
	}
	return &out, nil
}

// CompleteOAuthOptions configures CompleteOAuth.
type CompleteOAuthOptions struct {
	ProviderDomain string
	ClientID       string
}

// generateCodeVerifier returns a 128-character base64url PKCE verifier
// (96 random bytes encoded).
func generateCodeVerifier() (string, error) {
	b := make([]byte, 96)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// codeChallenge returns base64url(SHA-256(verifier)) per RFC 7636 §4.2.
func codeChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// resolveKeyWithStaleFlag wraps the key resolver and tracks whether a stale
// cache entry was used as a fallback.
func (c *Client) resolveKeyWithStaleFlag(ctx context.Context, providerID string) (ed25519.PublicKey, bool, error) {
	if rkr, ok := c.keyResolver.(*RegistryKeyResolver); ok {
		return rkr.resolvePublicKeyWithStaleFlag(ctx, providerID)
	}
	key, err := c.keyResolver.ResolvePublicKey(ctx, providerID)
	return key, false, err
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
// Expected format: {derived_id}@id.{provider_domain}
// e.g. "xK7mN2pR9sT4vW6yB@id.humanidentity.io" → "humanidentity.io"
// The "id." prefix is a namespace marker preventing collision with real emails.
func extractProviderFromSubject(subjectID string) (string, error) {
	idx := strings.LastIndex(subjectID, "@")
	if idx < 0 || idx == len(subjectID)-1 {
		return "", fmt.Errorf("hip: invalid subject_id format: %q", subjectID)
	}
	host := subjectID[idx+1:]
	if !strings.HasPrefix(host, "id.") {
		return "", fmt.Errorf("hip: missing id. prefix: %q", subjectID)
	}
	providerDomain := strings.TrimPrefix(host, "id.")
	if providerDomain == "" {
		return "", fmt.Errorf("hip: empty provider_domain: %q", subjectID)
	}
	return providerDomain, nil
}

// --- JWS verification (self-contained, no external deps) ---

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
	key, _, err := r.resolvePublicKeyWithStaleFlag(ctx, providerID)
	return key, err
}

// resolvePublicKeyWithStaleFlag is the internal implementation that also reports
// whether a stale cache entry was used as a fallback.
func (r *RegistryKeyResolver) resolvePublicKeyWithStaleFlag(ctx context.Context, providerID string) (ed25519.PublicKey, bool, error) {
	r.mu.RLock()
	cached := r.cache[providerID]
	r.mu.RUnlock()

	if cached != nil && time.Since(cached.fetchedAt) < r.ttl {
		return cached.key, false, nil
	}

	// Fetch from registry.
	url := fmt.Sprintf("%s/providers/%s/certificate", r.registryURL, providerID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		if cached != nil {
			return cached.key, true, nil // stale fallback
		}
		return nil, false, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		if cached != nil {
			return cached.key, true, nil // stale fallback
		}
		return nil, false, fmt.Errorf("hip: registry request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		if cached != nil {
			return cached.key, true, nil // stale fallback
		}
		return nil, false, fmt.Errorf("hip: registry returned %d for %s", resp.StatusCode, providerID)
	}

	var certResp struct {
		PublicKey string `json:"public_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&certResp); err != nil {
		if cached != nil {
			return cached.key, true, nil // stale fallback
		}
		return nil, false, fmt.Errorf("hip: decoding registry response: %w", err)
	}

	pubKey, err := ParsePEMPublicKey(certResp.PublicKey)
	if err != nil {
		if cached != nil {
			return cached.key, true, nil // stale fallback
		}
		return nil, false, err
	}

	r.mu.Lock()
	r.cache[providerID] = &cachedKey{key: pubKey, fetchedAt: time.Now()}
	r.mu.Unlock()

	return pubKey, false, nil
}
