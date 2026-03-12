package http

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/LCGant/role-notification/internal/config"
	"github.com/LCGant/role-notification/internal/delivery"
	"github.com/LCGant/role-notification/internal/sender"
)

func TestInternalVerificationRequiresToken(t *testing.T) {
	cfg := config.Config{InternalToken: "secret", MetricsToken: "metrics", QueueDir: t.TempDir(), QueueKey: bytes.Repeat([]byte{1}, 32), Mail: config.MailConfig{OutboxDir: t.TempDir()}}
	queue := delivery.New(cfg.QueueDir, cfg.QueueKey, sender.New(cfg.Mail), slog.New(slog.NewTextHandler(io.Discard, nil)))
	h := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), queue)

	req := httptest.NewRequest("POST", "/internal/email-verification", bytes.NewBufferString(`{"to":"u@example.com","token":"abc"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestVerificationWritesOutbox(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Config{InternalToken: "secret", MetricsToken: "metrics", QueueDir: t.TempDir(), QueueKey: bytes.Repeat([]byte{2}, 32), Mail: config.MailConfig{OutboxDir: dir}}
	queue := delivery.New(cfg.QueueDir, cfg.QueueKey, sender.New(cfg.Mail), slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go queue.Run(ctx)
	h := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), queue)

	req := httptest.NewRequest("POST", "/internal/email-verification", bytes.NewBufferString(`{"to":"u@example.com","token":"abc"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Token", "secret")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", rr.Code)
	}
	waitForOutboxToken(t, dir, "abc")
}

func TestInternalVerificationRejectsTrailingJSONData(t *testing.T) {
	cfg := config.Config{InternalToken: "secret", MetricsToken: "metrics", QueueDir: t.TempDir(), QueueKey: bytes.Repeat([]byte{3}, 32), Mail: config.MailConfig{OutboxDir: t.TempDir()}}
	queue := delivery.New(cfg.QueueDir, cfg.QueueKey, sender.New(cfg.Mail), slog.New(slog.NewTextHandler(io.Discard, nil)))
	h := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), queue)

	req := httptest.NewRequest("POST", "/internal/email-verification", bytes.NewBufferString("{\"to\":\"u@example.com\",\"token\":\"abc\"}junk"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Token", "secret")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func waitForOutboxToken(t *testing.T, dir, token string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		files, err := os.ReadDir(dir)
		if err == nil && len(files) > 0 {
			data, err := os.ReadFile(filepath.Join(dir, files[0].Name()))
			if err == nil && bytes.Contains(data, []byte(token)) {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("expected token %q in outbox %s", token, dir)
}
