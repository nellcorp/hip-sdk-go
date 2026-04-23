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
			RequestID:  req.RequestID,
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
			RequestID: req.RequestID,
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

func TestVerify_AutoGeneratesNonceAndRequestID(t *testing.T) {
	_, priv := generateTestKeyPair(t)

	var receivedReq VerifyRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedReq)
		resp := VerifyResponse{
			RequestID: receivedReq.RequestID,
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
	if receivedReq.RequestID == "" {
		t.Fatal("expected auto-generated request ID")
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
