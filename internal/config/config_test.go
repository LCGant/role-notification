package config

import (
	"encoding/base64"
	"testing"
)

func TestLoadRejectsProductionOutbox(t *testing.T) {
	t.Setenv("NOTIFICATION_EMAIL_VERIFICATION_INTERNAL_TOKEN", "verify-secret")
	t.Setenv("NOTIFICATION_PASSWORD_RESET_INTERNAL_TOKEN", "reset-secret")
	t.Setenv("NOTIFICATION_ENV", "production")
	t.Setenv("NOTIFICATION_QUEUE_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("EMAIL_OUTBOX_DIR", t.TempDir())

	if _, err := Load(); err == nil {
		t.Fatalf("expected production outbox configuration to be rejected")
	}
}

func TestLoadAcceptsVersionedQueueKeys(t *testing.T) {
	t.Setenv("NOTIFICATION_EMAIL_VERIFICATION_INTERNAL_TOKEN", "verify-secret")
	t.Setenv("NOTIFICATION_PASSWORD_RESET_INTERNAL_TOKEN", "reset-secret")
	t.Setenv("NOTIFICATION_QUEUE_ENCRYPTION_KEYS", "v1="+base64.StdEncoding.EncodeToString(make([]byte, 32))+",v2="+base64.StdEncoding.EncodeToString(bytesRepeat(3, 32)))
	t.Setenv("NOTIFICATION_QUEUE_ENCRYPTION_KEY_VERSION", "v2")
	t.Setenv("EMAIL_OUTBOX_DIR", t.TempDir())
	t.Setenv("NOTIFICATION_SERVICE_TOKEN_PUBLIC_KEYS", "auth-internal-default=LzMbiiOlgX5h9yVEmSwNFnJqWJeUXpgSg5VC99OCmPA=")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.QueueKeyVersion != "v2" || len(cfg.QueueKeys) != 2 {
		t.Fatalf("unexpected queue key config: version=%q keys=%d", cfg.QueueKeyVersion, len(cfg.QueueKeys))
	}
}

func TestLoadRejectsDisallowedAuthHost(t *testing.T) {
	t.Setenv("NOTIFICATION_EMAIL_VERIFICATION_INTERNAL_TOKEN", "verify-secret")
	t.Setenv("NOTIFICATION_PASSWORD_RESET_INTERNAL_TOKEN", "reset-secret")
	t.Setenv("NOTIFICATION_QUEUE_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("EMAIL_OUTBOX_DIR", t.TempDir())
	t.Setenv("NOTIFICATION_SERVICE_TOKEN_PUBLIC_KEYS", "auth-internal-default=LzMbiiOlgX5h9yVEmSwNFnJqWJeUXpgSg5VC99OCmPA=")
	t.Setenv("NOTIFICATION_AUTH_BASE_URL", "https://evil.example.test")
	t.Setenv("NOTIFICATION_AUTH_ALLOWED_HOSTS", "auth,auth.internal")
	t.Setenv("NOTIFICATION_AUTH_SERVICE_TOKEN_MINT_TOKEN", "mint-secret")

	if _, err := Load(); err == nil {
		t.Fatal("expected disallowed auth host to be rejected")
	}
}

func TestLoadAllowsConfiguredAuthHost(t *testing.T) {
	t.Setenv("NOTIFICATION_EMAIL_VERIFICATION_INTERNAL_TOKEN", "verify-secret")
	t.Setenv("NOTIFICATION_PASSWORD_RESET_INTERNAL_TOKEN", "reset-secret")
	t.Setenv("NOTIFICATION_QUEUE_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("EMAIL_OUTBOX_DIR", t.TempDir())
	t.Setenv("NOTIFICATION_SERVICE_TOKEN_PUBLIC_KEYS", "auth-internal-default=LzMbiiOlgX5h9yVEmSwNFnJqWJeUXpgSg5VC99OCmPA=")
	t.Setenv("NOTIFICATION_AUTH_BASE_URL", "https://auth.example.test")
	t.Setenv("NOTIFICATION_AUTH_ALLOWED_HOSTS", "auth,auth.internal,auth.example.test")
	t.Setenv("NOTIFICATION_AUTH_SERVICE_TOKEN_MINT_TOKEN", "mint-secret")

	if _, err := Load(); err != nil {
		t.Fatalf("expected configured auth host to be accepted: %v", err)
	}
}

func TestLoadDefaultsQueueStrictPermsByEnv(t *testing.T) {
	t.Setenv("NOTIFICATION_EMAIL_VERIFICATION_INTERNAL_TOKEN", "verify-secret")
	t.Setenv("NOTIFICATION_PASSWORD_RESET_INTERNAL_TOKEN", "reset-secret")
	t.Setenv("NOTIFICATION_QUEUE_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("EMAIL_OUTBOX_DIR", t.TempDir())
	t.Setenv("NOTIFICATION_SERVICE_TOKEN_PUBLIC_KEYS", "auth-internal-default=LzMbiiOlgX5h9yVEmSwNFnJqWJeUXpgSg5VC99OCmPA=")

	t.Setenv("NOTIFICATION_ENV", "development")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("load development config: %v", err)
	}
	if cfg.QueueRequireStrictPerms {
		t.Fatal("expected development config to relax strict queue perms by default")
	}

	t.Setenv("NOTIFICATION_ENV", "production")
	t.Setenv("EMAIL_OUTBOX_DIR", "")
	t.Setenv("SMTP_HOST", "smtp.example.test")
	t.Setenv("SMTP_FROM", "noreply@example.test")
	cfg, err = Load()
	if err != nil {
		t.Fatalf("load production config: %v", err)
	}
	if !cfg.QueueRequireStrictPerms {
		t.Fatal("expected production config to require strict queue perms by default")
	}
}

func bytesRepeat(value byte, count int) []byte {
	out := make([]byte, count)
	for i := range out {
		out[i] = value
	}
	return out
}
