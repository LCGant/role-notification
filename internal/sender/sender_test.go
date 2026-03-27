package sender

import (
	"testing"

	"github.com/LCGant/role-notification/internal/config"
)

func TestRenderTokenURLTemplateRejectsInvalidPlaceholderUsage(t *testing.T) {
	cfg := config.MailConfig{EmailVerificationURLTemplate: "https://example.test/verify?token={{token}}&copy={{token}}"}
	body := verificationBody(cfg, "abc")
	if body == "" || body == "https://example.test/verify?token=abc&copy=abc" {
		t.Fatalf("expected invalid template to fall back to code body")
	}
}
