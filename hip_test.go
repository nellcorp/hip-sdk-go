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

// staticKeyResolver returns a fixed public key for any provider.
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

		// Sign the response.
		respWithoutSig := resp
		payload, _ := json.Marshal(respWithoutSig)
		resp.Signature = signJWSForTest(t, priv, payload)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	c := New("test-key", "test-secret",
		WithKeyResolver(&staticKeyResolver{key: pub}),
	)

	resp, err := c.Verify(context.Background(), srv.URL, VerifyRequest{
		SubjectID: "abc123",
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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := VerifyResponse{
			Status: "active",
			Nonce:  "wrong-nonce",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	c := New("key", "secret")
	_, err := c.Verify(context.Background(), srv.URL, VerifyRequest{
		SubjectID: "abc123",
		Nonce:     "my-nonce",
	})
	if err == nil || !strings.Contains(err.Error(), "nonce mismatch") {
		t.Fatalf("expected nonce mismatch error, got %v", err)
	}
}

func TestVerify_InvalidSignature(t *testing.T) {
	pub, _ := generateTestKeyPair(t)
	_, otherPriv := generateTestKeyPair(t) // different key

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
		resp.Signature = signJWSForTest(t, otherPriv, payload) // signed with wrong key

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	c := New("key", "secret", WithKeyResolver(&staticKeyResolver{key: pub}))
	_, err := c.Verify(context.Background(), srv.URL, VerifyRequest{SubjectID: "abc123"})
	if err == nil || !strings.Contains(err.Error(), "invalid signature") {
		t.Fatalf("expected invalid signature error, got %v", err)
	}
}

func TestVerify_MissingSubjectID(t *testing.T) {
	c := New("key", "secret")
	_, err := c.Verify(context.Background(), "http://example.com", VerifyRequest{})
	if err == nil || !strings.Contains(err.Error(), "subject_id is required") {
		t.Fatalf("expected subject_id error, got %v", err)
	}
}

func TestVerify_AutoGeneratesNonceAndRequestID(t *testing.T) {
	var receivedReq VerifyRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedReq)
		resp := VerifyResponse{
			RequestID: receivedReq.RequestID,
			SubjectID: receivedReq.SubjectID,
			Status:    "active",
			Nonce:     receivedReq.Nonce,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	c := New("key", "secret")
	_, err := c.Verify(context.Background(), srv.URL, VerifyRequest{SubjectID: "abc123"})
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

	c := New("key", "secret")
	_, err := c.Verify(context.Background(), srv.URL, VerifyRequest{SubjectID: "abc123"})
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("expected 500 error, got %v", err)
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

func TestExtractProviderID(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"https://provider.example.com/.well-known/identity", "provider.example.com"},
		{"https://provider.example.com:8443/.well-known/identity", "provider.example.com"},
		{"http://localhost:8080/.well-known/identity", "localhost"},
		{"provider.example.com/.well-known/identity", "provider.example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got := extractProviderID(tt.url)
			if got != tt.want {
				t.Fatalf("extractProviderID(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
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

	// Second call should be cached (server can go down).
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

	// Populate cache.
	_, err := resolver.ResolvePublicKey(context.Background(), "fallback.com")
	if err != nil {
		t.Fatal(err)
	}

	// Kill server, let cache expire.
	srv.Close()
	time.Sleep(5 * time.Millisecond)

	// Should fall back to last-known-good.
	key, err := resolver.ResolvePublicKey(context.Background(), "fallback.com")
	if err != nil {
		t.Fatalf("expected fallback, got error: %v", err)
	}
	if !pub.Equal(key) {
		t.Fatal("fallback key doesn't match")
	}
}
