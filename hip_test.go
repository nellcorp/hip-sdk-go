package hip

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func generateTestKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func signJWSForTest(t *testing.T, priv ed25519.PrivateKey, payload []byte) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"JWT"}`))
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	signingInput := header + "." + encodedPayload
	sig := ed25519.Sign(priv, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func encodePEMPublicKey(pub ed25519.PublicKey) string {
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: pub}
	return string(pem.EncodeToMemory(block))
}

type staticKeyResolver struct {
	key ed25519.PublicKey
}

func (r *staticKeyResolver) ResolvePublicKey(_ context.Context, _ string) (ed25519.PublicKey, error) {
	return r.key, nil
}

func TestVerify_Success(t *testing.T) {
	pub, priv := generateTestKeyPair(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/verify" {
			http.NotFound(w, r)
			return
		}
		var req VerifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		resp := VerifyResponse{
			SubjectID:  req.SubjectID,
			Status:     "active",
			Score:      95,
			ScoreState: "stable",
			Nonce:      req.Nonce,
			IssuedAt:   time.Now(),
			ExpiresAt:  time.Now().Add(24 * time.Hour),
		}

		payload, _ := json.Marshal(resp)
		jws := signJWSForTest(t, priv, payload)

		w.Header().Set("Content-Type", "application/jose")
		_, _ = w.Write([]byte(jws))
	}))
	defer srv.Close()

	c := New("test-key",
		WithProviderURL(srv.URL),
		WithKeyResolver(&staticKeyResolver{key: pub}),
	)

	resp, err := c.Verify(context.Background(), VerifyRequest{
		SubjectID: "xK7mN2pR9sT4vW6yB@id.provider.example.com",
		Purpose:   "account_creation",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != "active" {
		t.Fatalf("expected active, got %s", resp.Status)
	}
	if resp.Score != 95 {
		t.Fatalf("expected score 95, got %d", resp.Score)
	}
}

func TestVerify_NonceMismatch(t *testing.T) {
	_, priv := generateTestKeyPair(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := VerifyResponse{
			Status: "active",
			Nonce:  "wrong-nonce",
		}
		payload, _ := json.Marshal(resp)
		jws := signJWSForTest(t, priv, payload)

		w.Header().Set("Content-Type", "application/jose")
		_, _ = w.Write([]byte(jws))
	}))
	defer srv.Close()

	c := New("key", WithProviderURL(srv.URL))
	_, err := c.Verify(context.Background(), VerifyRequest{
		SubjectID: "xK7mN2pR9sT4vW6yB@id.provider.example.com",
		Nonce:     "my-nonce",
	})
	if err == nil || !strings.Contains(err.Error(), "nonce mismatch") {
		t.Fatalf("expected nonce mismatch error, got %v", err)
	}
}

func TestVerify_InvalidSignature(t *testing.T) {
	pub, _ := generateTestKeyPair(t)
	_, otherPriv := generateTestKeyPair(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req VerifyRequest
		_ = json.NewDecoder(r.Body).Decode(&req)

		resp := VerifyResponse{
			SubjectID: req.SubjectID,
			Status:    "active",
			Nonce:     req.Nonce,
		}
		payload, _ := json.Marshal(resp)
		// Sign with wrong key to cause signature verification to fail
		jws := signJWSForTest(t, otherPriv, payload)

		w.Header().Set("Content-Type", "application/jose")
		_, _ = w.Write([]byte(jws))
	}))
	defer srv.Close()

	c := New("key",
		WithProviderURL(srv.URL),
		WithKeyResolver(&staticKeyResolver{key: pub}),
	)
	_, err := c.Verify(context.Background(), VerifyRequest{SubjectID: "xK7mN2pR9sT4vW6yB@id.provider.example.com"})
	if err == nil || !strings.Contains(err.Error(), "invalid signature") {
		t.Fatalf("expected invalid signature error, got %v", err)
	}
}

func TestVerify_MissingSubjectID(t *testing.T) {
	c := New("key")
	_, err := c.Verify(context.Background(), VerifyRequest{})
	if err == nil || !strings.Contains(err.Error(), "subject_id is required") {
		t.Fatalf("expected subject_id error, got %v", err)
	}
}

func TestVerify_InvalidSubjectIDFormat(t *testing.T) {
	c := New("key")
	_, err := c.Verify(context.Background(), VerifyRequest{SubjectID: "no-at-sign"})
	if err == nil || !strings.Contains(err.Error(), "invalid subject_id format") {
		t.Fatalf("expected format error, got %v", err)
	}
}

func TestVerify_AutoGeneratesNonce(t *testing.T) {
	_, priv := generateTestKeyPair(t)

	var receivedReq VerifyRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedReq)
		resp := VerifyResponse{
			SubjectID: receivedReq.SubjectID,
			Status:    "active",
			Nonce:     receivedReq.Nonce,
			IssuedAt:  time.Now(),
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}
		payload, _ := json.Marshal(resp)
		jws := signJWSForTest(t, priv, payload)

		w.Header().Set("Content-Type", "application/jose")
		_, _ = w.Write([]byte(jws))
	}))
	defer srv.Close()

	c := New("key", WithProviderURL(srv.URL))
	_, err := c.Verify(context.Background(), VerifyRequest{SubjectID: "xK7mN2pR9sT4vW6yB@id.provider.example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedReq.Nonce == "" {
		t.Fatal("expected auto-generated nonce")
	}
}

func TestVerify_ProviderError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal"}`))
	}))
	defer srv.Close()

	c := New("key", WithProviderURL(srv.URL))
	_, err := c.Verify(context.Background(), VerifyRequest{SubjectID: "xK7mN2pR9sT4vW6yB@id.provider.example.com"})
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("expected 500 error, got %v", err)
	}
}

func TestExtractProviderFromSubject(t *testing.T) {
	tests := []struct {
		subject string
		want    string
		wantErr bool
	}{
		// Valid format: {derived_id}@id.{provider_domain}
		{"xK7mN2pR9sT4vW6yB@id.humanidentity.io", "humanidentity.io", false},
		{"abc123def456@id.humanidentity.io", "humanidentity.io", false},
		{"short@id.example.com", "example.com", false},
		// Missing id. prefix
		{"abc123@provider.example.com", "", true},
		{"hex456@humanidentity.io", "", true},
		// Invalid format
		{"no-at-sign", "", true},
		{"trailing@", "", true},
		{"trailing@id.", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.subject, func(t *testing.T) {
			got, err := extractProviderFromSubject(tt.subject)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParsePEMPublicKey(t *testing.T) {
	pub, _ := generateTestKeyPair(t)
	pemStr := encodePEMPublicKey(pub)

	parsed, err := ParsePEMPublicKey(pemStr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !pub.Equal(parsed) {
		t.Fatal("parsed key doesn't match original")
	}
}

func TestParsePEMPublicKey_Invalid(t *testing.T) {
	_, err := ParsePEMPublicKey("not a pem")
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestRegistryKeyResolver(t *testing.T) {
	pub, _ := generateTestKeyPair(t)
	pemKey := encodePEMPublicKey(pub)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"public_key": pemKey})
	}))
	defer srv.Close()

	resolver := NewRegistryKeyResolver(srv.URL, 24*time.Hour)
	key, err := resolver.ResolvePublicKey(context.Background(), "test.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !pub.Equal(key) {
		t.Fatal("resolved key doesn't match")
	}

	// Second call should be cached.
	srv.Close()
	key2, err := resolver.ResolvePublicKey(context.Background(), "test.com")
	if err != nil {
		t.Fatalf("cached call failed: %v", err)
	}
	if !pub.Equal(key2) {
		t.Fatal("cached key doesn't match")
	}
}

func TestRegistryKeyResolver_Fallback(t *testing.T) {
	pub, _ := generateTestKeyPair(t)
	pemKey := encodePEMPublicKey(pub)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"public_key": pemKey})
	}))

	resolver := NewRegistryKeyResolver(srv.URL, 1*time.Millisecond)
	_, err := resolver.ResolvePublicKey(context.Background(), "fallback.com")
	if err != nil {
		t.Fatal(err)
	}

	srv.Close()
	time.Sleep(5 * time.Millisecond)

	key, err := resolver.ResolvePublicKey(context.Background(), "fallback.com")
	if err != nil {
		t.Fatalf("expected fallback, got error: %v", err)
	}
	if !pub.Equal(key) {
		t.Fatal("fallback key doesn't match")
	}
}

// --- OAuth / PKCE ---

func TestStartOAuth(t *testing.T) {
	c := New("key")
	flow, err := c.StartOAuth(OAuthStartOptions{
		ProviderDomain: "provider.example.com",
		ClientID:       "my-platform",
		RedirectURI:    "https://my-platform.example.com/oauth/callback",
		State:          "csrf123",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if flow.Verifier == "" || len(flow.Verifier) != 128 {
		t.Errorf("verifier length = %d, want 128", len(flow.Verifier))
	}
	if !strings.HasPrefix(flow.AuthorizeURL, "https://provider.example.com/oauth/authorize?") {
		t.Errorf("unexpected authorize URL: %s", flow.AuthorizeURL)
	}
	if !strings.Contains(flow.AuthorizeURL, "code_challenge=") {
		t.Errorf("missing code_challenge in URL: %s", flow.AuthorizeURL)
	}
	if !strings.Contains(flow.AuthorizeURL, "code_challenge_method=S256") {
		t.Errorf("missing S256 method: %s", flow.AuthorizeURL)
	}
	if !strings.Contains(flow.AuthorizeURL, "state=csrf123") {
		t.Errorf("missing state: %s", flow.AuthorizeURL)
	}
}

func TestStartOAuth_MissingClientID(t *testing.T) {
	c := New("key")
	_, err := c.StartOAuth(OAuthStartOptions{RedirectURI: "https://x/cb"})
	if err == nil || !strings.Contains(err.Error(), "ClientID") {
		t.Fatalf("expected ClientID error, got %v", err)
	}
}

func TestCodeChallenge_RFC7636TestVector(t *testing.T) {
	// RFC 7636 Appendix B.
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	want := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	got := codeChallenge(verifier)
	if got != want {
		t.Errorf("codeChallenge(%q) = %q, want %q", verifier, got, want)
	}
}

func TestCompleteOAuth(t *testing.T) {
	var receivedBody map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Errorf("Authorization header must NOT be sent; got %q", r.Header.Get("Authorization"))
		}
		_ = json.NewDecoder(r.Body).Decode(&receivedBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"subject_id":"sid","status":"active","score":95,"score_state":"stable","attestation":"a.b.c","issued_at":"2026-04-24T00:00:00Z","expires_at":"2026-04-24T00:05:00Z"}`))
	}))
	defer srv.Close()

	c := New("shouldNotBeSent", WithProviderURL(srv.URL))
	resp, err := c.CompleteOAuth(context.Background(), "the-code", "the-verifier-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", CompleteOAuthOptions{
		ProviderDomain: "provider.example.com",
		ClientID:       "my-platform",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.SubjectID != "sid" {
		t.Errorf("subject_id = %q", resp.SubjectID)
	}
	if receivedBody["grant_type"] != "authorization_code" {
		t.Errorf("grant_type = %q", receivedBody["grant_type"])
	}
	if receivedBody["code"] != "the-code" {
		t.Errorf("code = %q", receivedBody["code"])
	}
	if receivedBody["client_id"] != "my-platform" {
		t.Errorf("client_id = %q", receivedBody["client_id"])
	}
	if receivedBody["code_verifier"] != "the-verifier-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" {
		t.Errorf("code_verifier = %q", receivedBody["code_verifier"])
	}
}

// --- HIP/1.1 registry-driven discovery ---

// staticProviderResolver returns a fixed ProviderEntry without hitting the network.
type staticProviderResolver struct {
	entry *ProviderEntry
}

func (r *staticProviderResolver) ResolvePublicKey(ctx context.Context, providerID string) (ed25519.PublicKey, error) {
	return nil, errors.New("not implemented")
}

func (r *staticProviderResolver) ResolveProvider(ctx context.Context, providerID string) (*ProviderEntry, error) {
	if r.entry == nil || r.entry.ID != providerID {
		return nil, errors.New("not found")
	}
	entry := *r.entry
	return &entry, nil
}

// pemEncodePublicKey is a test-local helper. The SDK does not export PEM encoding.
func pemEncodePublicKey(t *testing.T, pub ed25519.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func TestProviderEntry_VerifyURLAccessor(t *testing.T) {
	cases := []struct {
		name string
		p    ProviderEntry
		want string
	}{
		{
			"hip/1.1 endpoints win",
			ProviderEntry{
				Endpoints:    ProviderEndpoints{Verify: "https://api.example.com/.well-known/hip/verify"},
				WellKnownURL: "https://example.com/.well-known/hip/", // ignored
			},
			"https://api.example.com/.well-known/hip/verify",
		},
		{
			"hip/1.0 fallback derives from well_known_url",
			ProviderEntry{WellKnownURL: "https://example.com/.well-known/hip/"},
			"https://example.com/.well-known/hip/verify",
		},
		{"empty entry", ProviderEntry{}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.p.VerifyURL(); got != tc.want {
				t.Errorf("VerifyURL() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestVerify_UsesRegistryDiscoveredEndpoints(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)

	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/hip/verify" {
			t.Errorf("Verify path = %q, want /.well-known/hip/verify", r.URL.Path)
		}
		var req VerifyRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		payload, _ := json.Marshal(VerifyResponse{
			SubjectID: req.SubjectID, Status: "active", Score: 80, Nonce: req.Nonce,
			IssuedAt:  time.Now(),
			ExpiresAt: time.Now().Add(5 * time.Minute),
		})
		jws := signJWSForTest(t, priv, payload)
		w.Header().Set("Content-Type", "application/jose")
		_, _ = w.Write([]byte(jws))
	}))
	defer apiSrv.Close()

	resolver := &staticProviderResolver{entry: &ProviderEntry{
		ID:        "provider.example.com",
		PublicKey: pemEncodePublicKey(t, pub),
		Endpoints: ProviderEndpoints{
			Verify: apiSrv.URL + "/.well-known/hip/verify",
		},
	}}

	c := New("key",
		WithKeyResolver(&staticKeyResolver{key: pub}),
		WithProviderResolverForTest(resolver),
	)
	resp, err := c.Verify(context.Background(), VerifyRequest{
		SubjectID: "xK7m@id.provider.example.com",
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if resp.Score != 80 {
		t.Errorf("score = %d", resp.Score)
	}
}

func TestStartOAuth_UsesRegistryDiscoveredAuthorizeURL(t *testing.T) {
	resolver := &staticProviderResolver{entry: &ProviderEntry{
		ID: "provider.example.com",
		Endpoints: ProviderEndpoints{
			OAuthAuthorize: "https://identity.example.com/oauth/authorize",
			OAuthToken:     "https://api.example.com/oauth/token",
		},
	}}
	c := New("key",
		WithKeyResolver(&staticKeyResolver{key: ed25519.PublicKey(make([]byte, 32))}),
		WithProviderResolverForTest(resolver),
	)
	flow, err := c.StartOAuthCtx(context.Background(), OAuthStartOptions{
		ProviderDomain: "provider.example.com",
		ClientID:       "my-platform",
		RedirectURI:    "https://platform.example.com/cb",
		State:          "csrf",
	})
	if err != nil {
		t.Fatalf("StartOAuthCtx: %v", err)
	}
	if !strings.HasPrefix(flow.AuthorizeURL, "https://identity.example.com/oauth/authorize?") {
		t.Errorf("AuthorizeURL = %q (must start with identity host, not provider domain)", flow.AuthorizeURL)
	}
}

func TestStartOAuth_HIP10FallbackWhenNoRegistryEntry(t *testing.T) {
	resolver := &staticProviderResolver{entry: nil}
	c := New("key",
		WithKeyResolver(&staticKeyResolver{key: ed25519.PublicKey(make([]byte, 32))}),
		WithProviderResolverForTest(resolver),
	)
	flow, err := c.StartOAuthCtx(context.Background(), OAuthStartOptions{
		ProviderDomain: "provider.example.com",
		ClientID:       "my-platform",
		RedirectURI:    "https://platform.example.com/cb",
	})
	if err != nil {
		t.Fatalf("StartOAuthCtx: %v", err)
	}
	if !strings.HasPrefix(flow.AuthorizeURL, "https://provider.example.com/oauth/authorize?") {
		t.Errorf("AuthorizeURL = %q (HIP/1.0 fallback expected)", flow.AuthorizeURL)
	}
}

func TestNew_AutoCreatesRegistryResolverByDefault(t *testing.T) {
	c := New("key")
	if c.keyResolver == nil {
		t.Error("keyResolver should be auto-created when neither WithKeyResolver nor WithProviderURL is passed")
	}
	if c.providerResolver == nil {
		t.Error("providerResolver should be auto-created (RegistryKeyResolver implements both)")
	}
}

func TestNew_SkipsAutoResolverWhenProviderURLSet(t *testing.T) {
	c := New("key", WithProviderURL("https://localhost:8080"))
	if c.keyResolver != nil {
		t.Error("keyResolver should not be auto-created when WithProviderURL is set (dev mode bypass)")
	}
}

func TestWithRegistries_SetsList(t *testing.T) {
	c := New("key", WithRegistries([]string{"https://reg-a.example.com", "https://reg-b.example.com"}))
	if len(c.registryURLs) != 2 {
		t.Fatalf("registryURLs len = %d", len(c.registryURLs))
	}
	if c.registryURLs[0] != "https://reg-a.example.com" {
		t.Errorf("first registry = %q", c.registryURLs[0])
	}
}

// WithProviderResolverForTest is a test-only Option to inject a resolver into
// the client without going through the registry HTTP path. Lives in the test
// file so production code stays clean.
func WithProviderResolverForTest(pr ProviderResolver) Option {
	return func(c *Client) { c.providerResolver = pr }
}

// TestRegistryKeyResolver_JWSResponse exercises the HIP/1.1 JWS-everywhere
// path: when the registry returns application/jose and the resolver has a
// pinned root key, the body is verified before the payload is parsed.
func TestRegistryKeyResolver_JWSResponse(t *testing.T) {
	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	pub, _ := generateTestKeyPair(t)
	pemKey := encodePEMPublicKey(pub)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		body, _ := json.Marshal(map[string]string{"public_key": pemKey})
		jws := signJWSForTest(t, rootPriv, body)
		w.Header().Set("Content-Type", "application/jose")
		_, _ = w.Write([]byte(jws))
	}))
	defer srv.Close()

	resolver := NewRegistryKeyResolver(srv.URL, 24*time.Hour)
	resolver.SetRegistryRootKey(rootPub)

	key, err := resolver.ResolvePublicKey(context.Background(), "test.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !pub.Equal(key) {
		t.Fatal("resolved key doesn't match")
	}
}

// TestRegistryKeyResolver_JWSBadSignature verifies that a tampered JWS body
// is rejected. The resolver MUST NOT trust the payload when the signature
// fails to verify against the pinned root key.
func TestRegistryKeyResolver_JWSBadSignature(t *testing.T) {
	rootPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen rootPub: %v", err)
	}
	_, attackerPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen attackerPriv: %v", err)
	}
	pub, _ := generateTestKeyPair(t)
	pemKey := encodePEMPublicKey(pub)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		body, _ := json.Marshal(map[string]string{"public_key": pemKey})
		// JWS signed by an attacker (NOT the pinned rootPub).
		jws := signJWSForTest(t, attackerPriv, body)
		w.Header().Set("Content-Type", "application/jose")
		_, _ = w.Write([]byte(jws))
	}))
	defer srv.Close()

	resolver := NewRegistryKeyResolver(srv.URL, 24*time.Hour)
	resolver.SetRegistryRootKey(rootPub)

	_, err = resolver.ResolvePublicKey(context.Background(), "tampered.com")
	if err == nil {
		t.Fatal("expected JWS verify error, got nil")
	}
	if !strings.Contains(err.Error(), "JWS verify") {
		t.Fatalf("expected JWS verify error, got: %v", err)
	}
}

// TestRegistryKeyResolver_ResolveProvider_JWS exercises the same JWS-
// verification path on the full provider-entry endpoint.
func TestRegistryKeyResolver_ResolveProvider_JWS(t *testing.T) {
	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	entry := ProviderEntry{
		ID:     "humanidentity.io",
		Domain: "humanidentity.io",
		Endpoints: ProviderEndpoints{
			Verify:         "https://api.humanidentity.io/.well-known/hip/verify",
			OAuthAuthorize: "https://humanidentity.io/oauth/authorize",
			OAuthToken:     "https://api.humanidentity.io/oauth/token",
		},
		PeerRegistries: []string{},
	}
	body, _ := json.Marshal(entry)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		jws := signJWSForTest(t, rootPriv, body)
		w.Header().Set("Content-Type", "application/jose")
		_, _ = w.Write([]byte(jws))
	}))
	defer srv.Close()

	resolver := NewRegistryKeyResolver(srv.URL, 24*time.Hour)
	resolver.SetRegistryRootKey(rootPub)

	got, err := resolver.ResolveProvider(context.Background(), "humanidentity.io")
	if err != nil {
		t.Fatalf("ResolveProvider: %v", err)
	}
	if got.Endpoints.Verify != entry.Endpoints.Verify {
		t.Fatalf("Verify URL = %q", got.Endpoints.Verify)
	}
	if got.Endpoints.OAuthAuthorize != entry.Endpoints.OAuthAuthorize {
		t.Fatalf("OAuthAuthorize URL = %q", got.Endpoints.OAuthAuthorize)
	}
}
