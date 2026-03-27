package authclient

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	internaltoken "github.com/LCGant/role-internaltoken"
)

func TestLookupUserUsesMintedBearerToken(t *testing.T) {
	signer := testSigner(t)
	srv := newAuthServer(t, signer)
	defer srv.Close()

	client := New(srv.URL, "notification-mint-secret")
	user, err := client.LookupUser(t.Context(), 42, "tenant-1")
	if err != nil {
		t.Fatalf("lookup user: %v", err)
	}
	if user == nil || user.ID != 42 || user.TenantID != "tenant-1" {
		t.Fatalf("unexpected user: %+v", user)
	}
}

func TestIntrospectUsesMintedBearerToken(t *testing.T) {
	signer := testSigner(t)
	srv := newAuthServer(t, signer)
	defer srv.Close()

	client := New(srv.URL, "notification-mint-secret")
	subject, active, err := client.Introspect(t.Context(), "session-token", "device-token")
	if err != nil {
		t.Fatalf("introspect: %v", err)
	}
	if !active || subject == nil || subject.UserID != 42 || subject.TenantID != "tenant-1" {
		t.Fatalf("unexpected introspect result: active=%v subject=%+v", active, subject)
	}
}

func newAuthServer(t *testing.T, signer *internaltoken.Signer) *httptest.Server {
	t.Helper()
	verifier, err := internaltoken.NewVerifier("auth-internal", map[string]ed25519.PublicKey{
		"auth-internal-default": ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize)).Public().(ed25519.PublicKey),
	}, 15*time.Second)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/internal/service-tokens":
			if r.Header.Get("X-Internal-Token") != "notification-mint-secret" {
				t.Fatalf("unexpected mint token: %q", r.Header.Get("X-Internal-Token"))
			}
			var req serviceTokenMintRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode mint request: %v", err)
			}
			token, claims, err := signer.Mint("notification", "auth", req.Scope, "", time.Minute)
			if err != nil {
				t.Fatalf("mint token: %v", err)
			}
			_ = json.NewEncoder(w).Encode(serviceTokenMintResponse{
				Token: &serviceTokenPayload{
					Value:     token,
					ExpiresAt: claims.ExpiresAt.UTC().Format(time.RFC3339),
				},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/internal/users/42":
			verifyBearerClaims(t, verifier, r, "auth:users:read")
			if r.Header.Get("X-Tenant-Id") != "tenant-1" {
				t.Fatalf("unexpected tenant header: %q", r.Header.Get("X-Tenant-Id"))
			}
			_ = json.NewEncoder(w).Encode(userResponse{
				User: &User{ID: 42, TenantID: "tenant-1", Email: "user@example.com"},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/internal/sessions/introspect":
			verifyBearerClaims(t, verifier, r, "auth:sessions:introspect")
			_, _ = w.Write([]byte(`{"active":true,"subject":{"user_id":42,"tenant_id":"tenant-1","aal":2,"auth_time":"` + time.Now().UTC().Format(time.RFC3339) + `"},"session":{"id":99,"expires_at":"` + time.Now().UTC().Add(time.Hour).Format(time.RFC3339) + `"}}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
}

func verifyBearerClaims(t *testing.T, verifier *internaltoken.Verifier, r *http.Request, scope string) {
	t.Helper()
	authz := r.Header.Get("Authorization")
	if len(authz) <= len("Bearer ") || authz[:7] != "Bearer " {
		t.Fatalf("expected bearer token, got %q", authz)
	}
	claims, err := verifier.Verify(authz[7:], "auth")
	if err != nil {
		t.Fatalf("verify bearer token: %v", err)
	}
	if claims.Subject != "notification" || claims.Scope != scope || claims.TenantID != "" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func testSigner(t *testing.T) *internaltoken.Signer {
	t.Helper()
	signer, err := internaltoken.NewSigner("auth-internal", "auth-internal-default", bytes.Repeat([]byte{7}, ed25519.SeedSize))
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return signer
}
