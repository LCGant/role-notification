package sender

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	stdmail "net/mail"
	"net/smtp"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/LCGant/role-notification/internal/config"
)

type Sender interface {
	SendVerification(ctx context.Context, to, token string) error
	SendPasswordReset(ctx context.Context, to, token string) error
	SendSocial(ctx context.Context, to, subject, body string) error
}

func New(cfg config.MailConfig) Sender {
	if strings.TrimSpace(cfg.SMTPHost) != "" {
		return &smtpSender{cfg: cfg}
	}
	return &outboxSender{cfg: cfg}
}

type smtpSender struct {
	cfg config.MailConfig
}

func (s *smtpSender) SendVerification(ctx context.Context, to, token string) error {
	return s.send(ctx, to, "Verify your email", verificationBody(s.cfg, token))
}

func (s *smtpSender) SendPasswordReset(ctx context.Context, to, token string) error {
	return s.send(ctx, to, "Reset your password", passwordResetBody(s.cfg, token))
}

func (s *smtpSender) SendSocial(ctx context.Context, to, subject, body string) error {
	return s.send(ctx, to, strings.TrimSpace(subject), strings.TrimSpace(body))
}

func (s *smtpSender) send(ctx context.Context, to, subject, body string) error {
	fromAddress, toAddress, subject, err := normalizeMessageParts(s.cfg.SMTPFrom, to, subject)
	if err != nil {
		return err
	}
	addr := net.JoinHostPort(s.cfg.SMTPHost, strconv.Itoa(s.cfg.SMTPPort))
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	client, err := smtp.NewClient(conn, s.cfg.SMTPHost)
	if err != nil {
		_ = conn.Close()
		return err
	}
	defer client.Close()

	if ok, _ := client.Extension("STARTTLS"); ok {
		tlsCfg := &tls.Config{
			ServerName:         s.cfg.SMTPHost,
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: false,
		}
		if err := client.StartTLS(tlsCfg); err != nil {
			return err
		}
	} else if s.cfg.SMTPRequireTLS {
		return errors.New("smtp server does not support STARTTLS")
	}

	if s.cfg.SMTPUsername != "" {
		auth := smtp.PlainAuth("", s.cfg.SMTPUsername, s.cfg.SMTPPassword, s.cfg.SMTPHost)
		if err := client.Auth(auth); err != nil {
			return err
		}
	}

	msg, err := buildMessage(fromAddress, toAddress, subject, body)
	if err != nil {
		return err
	}
	if err := client.Mail(fromAddress); err != nil {
		return err
	}
	if err := client.Rcpt(toAddress); err != nil {
		return err
	}
	wc, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := wc.Write([]byte(msg)); err != nil {
		_ = wc.Close()
		return err
	}
	if err := wc.Close(); err != nil {
		return err
	}
	return client.Quit()
}

type outboxSender struct {
	cfg config.MailConfig
}

func (o *outboxSender) SendVerification(ctx context.Context, to, token string) error {
	return o.write(ctx, "verify", to, verificationBody(o.cfg, token))
}

func (o *outboxSender) SendPasswordReset(ctx context.Context, to, token string) error {
	return o.write(ctx, "reset", to, passwordResetBody(o.cfg, token))
}

func (o *outboxSender) SendSocial(ctx context.Context, to, subject, body string) error {
	message, err := buildMessage(o.cfg.SMTPFrom, to, strings.TrimSpace(subject), strings.TrimSpace(body))
	if err != nil {
		return err
	}
	return o.write(ctx, "social", to, message)
}

func (o *outboxSender) write(ctx context.Context, prefix, to, body string) error {
	_ = ctx
	if err := os.MkdirAll(o.cfg.OutboxDir, 0o700); err != nil {
		return err
	}
	name := fmt.Sprintf("%s-%d-%s.txt", prefix, time.Now().UTC().UnixNano(), sanitizeFilename(to))
	path := filepath.Join(o.cfg.OutboxDir, name)
	return os.WriteFile(path, []byte(body), 0o600)
}

func buildMessage(from, to, subject, body string) (string, error) {
	from, to, subject, err := normalizeMessageParts(from, to, subject)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("From: ")
	b.WriteString(from)
	b.WriteString("\r\n")
	b.WriteString("To: ")
	b.WriteString(to)
	b.WriteString("\r\n")
	b.WriteString("Subject: ")
	b.WriteString(subject)
	b.WriteString("\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(body)
	return b.String(), nil
}

func normalizeMessageParts(from, to, subject string) (string, string, string, error) {
	if strings.TrimSpace(from) == "" {
		from = "noreply@local.invalid"
	}
	fromAddress, err := normalizeAddress(from)
	if err != nil {
		return "", "", "", err
	}
	toAddress, err := normalizeAddress(to)
	if err != nil {
		return "", "", "", err
	}
	subject = strings.TrimSpace(subject)
	if subject == "" || strings.ContainsAny(subject, "\r\n") {
		return "", "", "", errors.New("invalid subject")
	}
	return fromAddress, toAddress, subject, nil
}

func normalizeAddress(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsAny(value, "\r\n") {
		return "", errors.New("invalid address")
	}
	addr, err := stdmail.ParseAddress(value)
	if err != nil || strings.TrimSpace(addr.Address) == "" {
		return "", errors.New("invalid address")
	}
	return strings.TrimSpace(addr.Address), nil
}

func verificationBody(cfg config.MailConfig, token string) string {
	token = strings.TrimSpace(token)
	if strings.TrimSpace(cfg.EmailVerificationURLTemplate) != "" {
		return strings.ReplaceAll(cfg.EmailVerificationURLTemplate, "{{token}}", token)
	}
	return fmt.Sprintf(
		"Use this verification token to activate your account:\n\n%s\n\nSubmit it to POST /email/verify/confirm or your frontend verification screen.\n",
		token,
	)
}

func passwordResetBody(cfg config.MailConfig, token string) string {
	token = strings.TrimSpace(token)
	if strings.TrimSpace(cfg.PasswordResetURLTemplate) != "" {
		return strings.ReplaceAll(cfg.PasswordResetURLTemplate, "{{token}}", token)
	}
	return fmt.Sprintf(
		"Use this password reset token to change your password:\n\n%s\n\nSubmit it to POST /password/reset or your frontend reset screen.\n",
		token,
	)
}

func sanitizeFilename(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	replacer := strings.NewReplacer("@", "_at_", "/", "_", "\\", "_", ":", "_", " ", "_")
	value = replacer.Replace(value)
	if value == "" {
		return "recipient"
	}
	return value
}
