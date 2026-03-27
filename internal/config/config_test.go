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

func bytesRepeat(value byte, count int) []byte {
	out := make([]byte, count)
	for i := range out {
		out[i] = value
	}
	return out
}
