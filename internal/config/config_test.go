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
