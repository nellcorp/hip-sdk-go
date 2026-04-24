package hip

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
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
		{"abc123def456@id.hip.dev", "hip.dev", false},
		{"short@id.example.com", "example.com", false},
		// Missing id. prefix
		{"abc123@provider.example.com", "", true},
		{"hex456@hip.dev", "", true},
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
