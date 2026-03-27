package config

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"strings"

	envconfig "github.com/LCGant/role-config"
	internaltoken "github.com/LCGant/role-internaltoken"
)

type Config struct {
	HTTPAddr                   string
	DBURL                      string
	VerificationInternalToken  string
	PasswordResetInternalToken string
	MetricsToken               string
	LogLevel                   string
	Env                        string
	QueueDir                   string
	QueueKey                   []byte
	QueueKeys                  map[string][]byte
	QueueKeyVersion            string
	AuthBaseURL                string
	AuthServiceTokenMintToken  string
	SessionCookie              string
	DeviceCookie               string
	AllowInsecureHTTP          bool
	ServiceTokenIssuer         string
	ServiceTokenAudience       string
	ServiceTokenPublicKeys     map[string]ed25519.PublicKey
	ServiceTokenReplayRedisURL string
	Mail                       MailConfig
}

type MailConfig struct {
	OutboxDir                    string
	SMTPHost                     string
	SMTPPort                     int
	SMTPUsername                 string
	SMTPPassword                 string
	SMTPFrom                     string
	SMTPRequireTLS               bool
	EmailVerificationURLTemplate string
	PasswordResetURLTemplate     string
}

func Load() (Config, error) {
	cfg := Config{
		HTTPAddr:                   envconfig.EnvString("NOTIFICATION_HTTP_ADDR", ":8080"),
		DBURL:                      strings.TrimSpace(envconfig.EnvString("NOTIFICATION_DB_URL", envconfig.EnvString("DATABASE_URL", ""))),
		VerificationInternalToken:  strings.TrimSpace(os.Getenv("NOTIFICATION_EMAIL_VERIFICATION_INTERNAL_TOKEN")),
		PasswordResetInternalToken: strings.TrimSpace(os.Getenv("NOTIFICATION_PASSWORD_RESET_INTERNAL_TOKEN")),
		MetricsToken:               strings.TrimSpace(os.Getenv("NOTIFICATION_METRICS_TOKEN")),
		LogLevel:                   envconfig.EnvString("NOTIFICATION_LOG_LEVEL", "info"),
		Env:                        envconfig.EnvString("NOTIFICATION_ENV", "development"),
		QueueDir:                   strings.TrimSpace(envconfig.EnvString("NOTIFICATION_QUEUE_DIR", "/tmp/notification-queue")),
		AuthBaseURL:                strings.TrimSpace(envconfig.EnvString("NOTIFICATION_AUTH_BASE_URL", "")),
		AuthServiceTokenMintToken:  strings.TrimSpace(envconfig.EnvString("NOTIFICATION_AUTH_SERVICE_TOKEN_MINT_TOKEN", "")),
		SessionCookie:              strings.TrimSpace(envconfig.EnvString("NOTIFICATION_SESSION_COOKIE", "session_id")),
		DeviceCookie:               strings.TrimSpace(envconfig.EnvString("NOTIFICATION_DEVICE_COOKIE", "device_id")),
		AllowInsecureHTTP:          envconfig.EnvBool("NOTIFICATION_AUTH_ALLOW_INSECURE_HTTP", false),
		ServiceTokenIssuer:         strings.TrimSpace(envconfig.EnvString("NOTIFICATION_SERVICE_TOKEN_ISSUER", "auth-internal")),
		ServiceTokenAudience:       strings.TrimSpace(envconfig.EnvString("NOTIFICATION_SERVICE_TOKEN_AUDIENCE", "notification")),
		ServiceTokenReplayRedisURL: strings.TrimSpace(os.Getenv("NOTIFICATION_SERVICE_TOKEN_REPLAY_REDIS_URL")),
		Mail: MailConfig{
			OutboxDir:                    strings.TrimSpace(os.Getenv("EMAIL_OUTBOX_DIR")),
			SMTPHost:                     strings.TrimSpace(os.Getenv("SMTP_HOST")),
			SMTPPort:                     envconfig.EnvInt("SMTP_PORT", 587),
			SMTPUsername:                 strings.TrimSpace(os.Getenv("SMTP_USERNAME")),
			SMTPPassword:                 strings.TrimSpace(os.Getenv("SMTP_PASSWORD")),
			SMTPFrom:                     strings.TrimSpace(os.Getenv("SMTP_FROM")),
			SMTPRequireTLS:               envconfig.EnvBool("SMTP_REQUIRE_TLS", true),
			EmailVerificationURLTemplate: os.Getenv("EMAIL_VERIFICATION_URL_TEMPLATE"),
			PasswordResetURLTemplate:     os.Getenv("PASSWORD_RESET_URL_TEMPLATE"),
		},
	}
	if cfg.VerificationInternalToken == "" {
		return Config{}, errors.New("NOTIFICATION_EMAIL_VERIFICATION_INTERNAL_TOKEN is required")
	}
	if cfg.PasswordResetInternalToken == "" {
		return Config{}, errors.New("NOTIFICATION_PASSWORD_RESET_INTERNAL_TOKEN is required")
	}
	if cfg.QueueDir == "" {
		return Config{}, errors.New("NOTIFICATION_QUEUE_DIR is required")
	}
	if keySet := strings.TrimSpace(os.Getenv("NOTIFICATION_QUEUE_ENCRYPTION_KEYS")); keySet != "" {
		keys, err := parseQueueKeys(keySet)
		if err != nil {
			return Config{}, err
		}
		cfg.QueueKeys = keys
		cfg.QueueKeyVersion = strings.TrimSpace(envconfig.EnvString("NOTIFICATION_QUEUE_ENCRYPTION_KEY_VERSION", ""))
		if cfg.QueueKeyVersion == "" {
			return Config{}, errors.New("NOTIFICATION_QUEUE_ENCRYPTION_KEY_VERSION is required when NOTIFICATION_QUEUE_ENCRYPTION_KEYS is set")
		}
		cfg.QueueKey = append([]byte(nil), cfg.QueueKeys[cfg.QueueKeyVersion]...)
		if len(cfg.QueueKey) != 32 {
			return Config{}, errors.New("NOTIFICATION_QUEUE_ENCRYPTION_KEY_VERSION must reference a configured queue key")
		}
	} else {
		keyB64 := strings.TrimSpace(os.Getenv("NOTIFICATION_QUEUE_ENCRYPTION_KEY"))
		key, err := base64.StdEncoding.DecodeString(keyB64)
		if err != nil || len(key) != 32 {
			return Config{}, errors.New("NOTIFICATION_QUEUE_ENCRYPTION_KEY must be 32 bytes base64")
		}
		cfg.QueueKey = key
		cfg.QueueKeys = map[string][]byte{"v1": append([]byte(nil), key...)}
		cfg.QueueKeyVersion = "v1"
	}
	if cfg.Mail.OutboxDir != "" && cfg.Mail.SMTPHost != "" {
		return Config{}, errors.New("EMAIL_OUTBOX_DIR and SMTP_HOST are mutually exclusive")
	}
	if cfg.Mail.OutboxDir == "" && cfg.Mail.SMTPHost == "" {
		return Config{}, errors.New("configure EMAIL_OUTBOX_DIR or SMTP_HOST for notification delivery")
	}
	if cfg.Mail.SMTPHost != "" {
		if cfg.Mail.SMTPPort <= 0 || cfg.Mail.SMTPPort > 65535 {
			return Config{}, errors.New("SMTP_PORT must be between 1 and 65535")
		}
		if cfg.Mail.SMTPFrom == "" {
			return Config{}, errors.New("SMTP_FROM is required when SMTP_HOST is set")
		}
		if (cfg.Mail.SMTPUsername == "") != (cfg.Mail.SMTPPassword == "") {
			return Config{}, errors.New("SMTP_USERNAME and SMTP_PASSWORD must be set together")
		}
	}
	if strings.EqualFold(strings.TrimSpace(cfg.Env), "production") && cfg.Mail.OutboxDir != "" {
		return Config{}, errors.New("EMAIL_OUTBOX_DIR is not allowed in production")
	}
	if cfg.AuthBaseURL != "" && cfg.AuthServiceTokenMintToken == "" {
		return Config{}, errors.New("NOTIFICATION_AUTH_SERVICE_TOKEN_MINT_TOKEN is required when NOTIFICATION_AUTH_BASE_URL is set")
	}
	if cfg.AuthBaseURL == "" && cfg.AuthServiceTokenMintToken != "" {
		return Config{}, errors.New("NOTIFICATION_AUTH_BASE_URL is required when NOTIFICATION_AUTH_SERVICE_TOKEN_MINT_TOKEN is set")
	}
	if rawKeys := strings.TrimSpace(os.Getenv("NOTIFICATION_SERVICE_TOKEN_PUBLIC_KEYS")); rawKeys != "" {
		keys, err := internaltoken.ParsePublicKeySet(rawKeys)
		if err != nil {
			return Config{}, errors.New("NOTIFICATION_SERVICE_TOKEN_PUBLIC_KEYS is invalid")
		}
		cfg.ServiceTokenPublicKeys = keys
	}
	if len(cfg.ServiceTokenPublicKeys) == 0 {
		return Config{}, errors.New("NOTIFICATION_SERVICE_TOKEN_PUBLIC_KEYS is required")
	}
	if len(cfg.ServiceTokenPublicKeys) > 0 {
		if cfg.ServiceTokenIssuer == "" || cfg.ServiceTokenAudience == "" {
			return Config{}, errors.New("NOTIFICATION_SERVICE_TOKEN_ISSUER and NOTIFICATION_SERVICE_TOKEN_AUDIENCE are required when NOTIFICATION_SERVICE_TOKEN_PUBLIC_KEYS is set")
		}
	}
	return cfg, nil
}

func parseQueueKeys(raw string) (map[string][]byte, error) {
	out := map[string][]byte{}
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		version, encoded, ok := strings.Cut(entry, "=")
		if !ok {
			return nil, errors.New("NOTIFICATION_QUEUE_ENCRYPTION_KEYS entries must use version=base64")
		}
		version = strings.TrimSpace(version)
		key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
		if err != nil || len(key) != 32 {
			return nil, errors.New("NOTIFICATION_QUEUE_ENCRYPTION_KEYS entries must decode to 32-byte keys")
		}
		out[version] = key
	}
	if len(out) == 0 {
		return nil, errors.New("NOTIFICATION_QUEUE_ENCRYPTION_KEYS must contain at least one key")
	}
	return out, nil
}
