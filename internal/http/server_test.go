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
	basestore "github.com/LCGant/role-notification/internal/store"
	"github.com/LCGant/role-notification/internal/store/memory"
)

func TestInternalVerificationRequiresToken(t *testing.T) {
	cfg := config.Config{InternalToken: "secret", MetricsToken: "metrics", QueueDir: t.TempDir(), QueueKey: bytes.Repeat([]byte{1}, 32), Mail: config.MailConfig{OutboxDir: t.TempDir()}}
	queue := delivery.New(cfg.QueueDir, cfg.QueueKey, sender.New(cfg.Mail), slog.New(slog.NewTextHandler(io.Discard, nil)))
	h := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), queue, memory.New())

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
	h := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), queue, memory.New())

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
	h := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), queue, memory.New())

	req := httptest.NewRequest("POST", "/internal/email-verification", bytes.NewBufferString("{\"to\":\"u@example.com\",\"token\":\"abc\"}junk"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Token", "secret")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestSocialNotificationWritesOutbox(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Config{InternalToken: "secret", MetricsToken: "metrics", QueueDir: t.TempDir(), QueueKey: bytes.Repeat([]byte{4}, 32), Mail: config.MailConfig{OutboxDir: dir}}
	queue := delivery.New(cfg.QueueDir, cfg.QueueKey, sender.New(cfg.Mail), slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go queue.Run(ctx)
	h := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), queue, memory.New())

	req := httptest.NewRequest("POST", "/internal/social", bytes.NewBufferString(`{"user_id":42,"tenant_id":"default","to":"u@example.com","kind":"follow","subject":"New follower","body":"Alice started following you."}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Token", "secret")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", rr.Code)
	}
	waitForOutboxToken(t, dir, "Alice started following you.")
}

type stubAuthn struct {
	viewer viewer
	err    error
}

func (s stubAuthn) Required(context.Context, *http.Request) (viewer, error) {
	return s.viewer, s.err
}

func TestNotificationInboxEndpoints(t *testing.T) {
	cfg := config.Config{InternalToken: "secret", QueueDir: t.TempDir(), QueueKey: bytes.Repeat([]byte{5}, 32), Mail: config.MailConfig{OutboxDir: t.TempDir()}}
	queue := delivery.New(cfg.QueueDir, cfg.QueueKey, sender.New(cfg.Mail), slog.New(slog.NewTextHandler(io.Discard, nil)))
	inbox := memory.New()
	authn := stubAuthn{viewer: viewer{UserID: 99, TenantID: "default"}}
	h := NewWithDependencies(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), queue, inbox, authn, nil)

	createdAt := time.Now().UTC()
	id1, err := newNotificationID()
	if err != nil {
		t.Fatalf("new id: %v", err)
	}
	id2, err := newNotificationID()
	if err != nil {
		t.Fatalf("new id: %v", err)
	}
	if _, err := inbox.CreateNotification(context.Background(), memoryNotification(id1, createdAt.Add(-time.Minute))); err != nil {
		t.Fatalf("seed notification 1: %v", err)
	}
	if _, err := inbox.CreateNotification(context.Background(), memoryNotification(id2, createdAt)); err != nil {
		t.Fatalf("seed notification 2: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/unread-count", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 unread count, got %d", rr.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/?limit=10&offset=0", nil)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 list, got %d", rr.Code)
	}
	if !bytes.Contains(rr.Body.Bytes(), []byte(id2)) {
		t.Fatalf("expected list response to contain notification %s, got %s", id2, rr.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/"+id2+"/read", nil)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 read, got %d", rr.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/read-all", nil)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 read-all, got %d", rr.Code)
	}
}

func memoryNotification(publicID string, createdAt time.Time) basestore.Notification {
	return basestore.Notification{
		PublicID:  publicID,
		TenantID:  "default",
		UserID:    99,
		Kind:      "follow",
		Subject:   "New follower",
		Body:      "Alice started following you.",
		CreatedAt: createdAt,
	}
}

func newNotificationID() (string, error) {
	return basestore.NewPublicID()
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
