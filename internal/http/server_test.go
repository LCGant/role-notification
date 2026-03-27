package http

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/LCGant/role-notification/internal/authclient"
	"github.com/LCGant/role-notification/internal/config"
	"github.com/LCGant/role-notification/internal/delivery"
	"github.com/LCGant/role-notification/internal/sender"
	basestore "github.com/LCGant/role-notification/internal/store"
	"github.com/LCGant/role-notification/internal/store/memory"
)

func TestInternalVerificationRequiresToken(t *testing.T) {
	cfg := config.Config{VerificationInternalToken: "verify-secret", PasswordResetInternalToken: "reset-secret", SocialInternalToken: "social-secret", MetricsToken: "metrics", QueueDir: t.TempDir(), QueueKey: bytes.Repeat([]byte{1}, 32), Mail: config.MailConfig{OutboxDir: t.TempDir()}}
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
	cfg := config.Config{VerificationInternalToken: "verify-secret", PasswordResetInternalToken: "reset-secret", SocialInternalToken: "social-secret", MetricsToken: "metrics", QueueDir: t.TempDir(), QueueKey: bytes.Repeat([]byte{2}, 32), Mail: config.MailConfig{OutboxDir: dir}}
	queue := delivery.New(cfg.QueueDir, cfg.QueueKey, sender.New(cfg.Mail), slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go queue.Run(ctx)
	h := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), queue, memory.New())

	req := httptest.NewRequest("POST", "/internal/email-verification", bytes.NewBufferString(`{"to":"u@example.com","token":"abc"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Token", "verify-secret")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", rr.Code)
	}
	waitForOutboxToken(t, dir, "abc")
}

func TestInternalVerificationRejectsTrailingJSONData(t *testing.T) {
	cfg := config.Config{VerificationInternalToken: "verify-secret", PasswordResetInternalToken: "reset-secret", SocialInternalToken: "social-secret", MetricsToken: "metrics", QueueDir: t.TempDir(), QueueKey: bytes.Repeat([]byte{3}, 32), Mail: config.MailConfig{OutboxDir: t.TempDir()}}
	queue := delivery.New(cfg.QueueDir, cfg.QueueKey, sender.New(cfg.Mail), slog.New(slog.NewTextHandler(io.Discard, nil)))
	h := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), queue, memory.New())

	req := httptest.NewRequest("POST", "/internal/email-verification", bytes.NewBufferString("{\"to\":\"u@example.com\",\"token\":\"abc\"}junk"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Token", "verify-secret")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestSocialNotificationWritesOutbox(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Config{VerificationInternalToken: "verify-secret", PasswordResetInternalToken: "reset-secret", SocialInternalToken: "social-secret", MetricsToken: "metrics", QueueDir: t.TempDir(), QueueKey: bytes.Repeat([]byte{4}, 32), Mail: config.MailConfig{OutboxDir: dir}}
	queue := delivery.New(cfg.QueueDir, cfg.QueueKey, sender.New(cfg.Mail), slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go queue.Run(ctx)
	authSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Internal-Token") != "lookup-secret" {
			t.Fatalf("unexpected auth lookup token")
		}
		if r.Header.Get("X-Tenant-Id") != "default" {
			t.Fatalf("unexpected tenant header")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"user":{"id":42,"tenant_id":"default","email":"u@example.com"}}`))
	}))
	defer authSrv.Close()
	h := NewWithDependencies(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), queue, memory.New(), nil, authclient.New(authSrv.URL, "lookup-secret"))

	req := httptest.NewRequest("POST", "/internal/social", bytes.NewBufferString(`{"user_id":42,"tenant_id":"default","kind":"follow","subject":"New follower","body":"Alice started following you."}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Token", "social-secret")
	req.Header.Set("X-Caller-Tenant-Id", "default")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", rr.Code)
	}
	waitForOutboxToken(t, dir, "Alice started following you.")
}

func TestSocialNotificationSanitizesHTMLBeforePersisting(t *testing.T) {
	cfg := config.Config{VerificationInternalToken: "verify-secret", PasswordResetInternalToken: "reset-secret", SocialInternalToken: "social-secret", MetricsToken: "metrics", QueueDir: t.TempDir(), QueueKey: bytes.Repeat([]byte{9}, 32), Mail: config.MailConfig{OutboxDir: t.TempDir()}}
	queue := delivery.New(cfg.QueueDir, cfg.QueueKey, sender.New(cfg.Mail), slog.New(slog.NewTextHandler(io.Discard, nil)))
	inbox := memory.New()
	authSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"user":{"id":42,"tenant_id":"default","email":"u@example.com"}}`))
	}))
	defer authSrv.Close()
	h := NewWithDependencies(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), queue, inbox, nil, authclient.New(authSrv.URL, "lookup-secret"))

	req := httptest.NewRequest("POST", "/internal/social", bytes.NewBufferString(`{"user_id":42,"tenant_id":"default","kind":"follow","subject":"<b>New follower</b>","body":"<script>alert(1)</script>Hello"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Token", "social-secret")
	req.Header.Set("X-Caller-Tenant-Id", "default")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d body=%s", rr.Code, rr.Body.String())
	}

	items, _, err := inbox.ListNotifications(context.Background(), "default", 42, 10, 0)
	if err != nil {
		t.Fatalf("list notifications: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 notification, got %d", len(items))
	}
	if items[0].Subject != "&lt;b&gt;New follower&lt;/b&gt;" {
		t.Fatalf("unexpected sanitized subject: %q", items[0].Subject)
	}
	if items[0].Body != "&lt;script&gt;alert(1)&lt;/script&gt;Hello" {
		t.Fatalf("unexpected sanitized body: %q", items[0].Body)
	}
}

func TestSocialNotificationRejectsMissingOrMismatchedCallerTenant(t *testing.T) {
	cfg := config.Config{VerificationInternalToken: "verify-secret", PasswordResetInternalToken: "reset-secret", SocialInternalToken: "social-secret", MetricsToken: "metrics", QueueDir: t.TempDir(), QueueKey: bytes.Repeat([]byte{9}, 32), Mail: config.MailConfig{OutboxDir: t.TempDir()}}
	queue := delivery.New(cfg.QueueDir, cfg.QueueKey, sender.New(cfg.Mail), slog.New(slog.NewTextHandler(io.Discard, nil)))
	inbox := memory.New()
	authSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"user":{"id":42,"tenant_id":"default","email":"u@example.com"}}`))
	}))
	defer authSrv.Close()
	h := NewWithDependencies(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), queue, inbox, nil, authclient.New(authSrv.URL, "lookup-secret"))

	req := httptest.NewRequest("POST", "/internal/social", bytes.NewBufferString(`{"user_id":42,"tenant_id":"default","kind":"follow","subject":"New follower","body":"Alice started following you."}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Token", "social-secret")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 without caller tenant header, got %d", rr.Code)
	}

	req = httptest.NewRequest("POST", "/internal/social", bytes.NewBufferString(`{"user_id":42,"tenant_id":"default","kind":"follow","subject":"New follower","body":"Alice started following you."}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Token", "social-secret")
	req.Header.Set("X-Caller-Tenant-Id", "tenant-99")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for mismatched caller tenant, got %d", rr.Code)
	}
}

type stubAuthn struct {
	viewer viewer
	err    error
}

func (s stubAuthn) Required(context.Context, *http.Request) (viewer, error) {
	return s.viewer, s.err
}

func TestNotificationInboxEndpoints(t *testing.T) {
	cfg := config.Config{VerificationInternalToken: "verify-secret", PasswordResetInternalToken: "reset-secret", SocialInternalToken: "social-secret", QueueDir: t.TempDir(), QueueKey: bytes.Repeat([]byte{5}, 32), Mail: config.MailConfig{OutboxDir: t.TempDir()}}
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
	var listResp struct {
		Notifications []struct {
			ID        string     `json:"id"`
			Kind      string     `json:"kind"`
			KindLabel string     `json:"kind_label"`
			KindGroup string     `json:"kind_group"`
			IsRead    bool       `json:"is_read"`
			ReadAt    *time.Time `json:"read_at"`
		} `json:"notifications"`
		Total       int  `json:"total"`
		UnreadCount int  `json:"unread_count"`
		Limit       int  `json:"limit"`
		Offset      int  `json:"offset"`
		HasMore     bool `json:"has_more"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("decode list response: %v body=%s", err, rr.Body.String())
	}
	if listResp.Total != 2 || listResp.UnreadCount != 2 || listResp.Limit != 10 || listResp.Offset != 0 || listResp.HasMore {
		t.Fatalf("unexpected list metadata: %+v", listResp)
	}
	if len(listResp.Notifications) != 2 || listResp.Notifications[0].ID != id2 {
		t.Fatalf("expected list response to contain notification %s first, got %+v", id2, listResp.Notifications)
	}
	if listResp.Notifications[0].KindLabel == "" || listResp.Notifications[0].KindGroup == "" || listResp.Notifications[0].IsRead {
		t.Fatalf("unexpected notification presentation: %+v", listResp.Notifications[0])
	}

	req = httptest.NewRequest(http.MethodPost, "/"+id2+"/read", nil)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 read, got %d", rr.Code)
	}
	var readResp struct {
		Notification struct {
			ID     string     `json:"id"`
			IsRead bool       `json:"is_read"`
			ReadAt *time.Time `json:"read_at"`
		} `json:"notification"`
		UnreadCount int `json:"unread_count"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &readResp); err != nil {
		t.Fatalf("decode read response: %v body=%s", err, rr.Body.String())
	}
	if readResp.Notification.ID != id2 || !readResp.Notification.IsRead || readResp.Notification.ReadAt == nil || readResp.UnreadCount != 1 {
		t.Fatalf("unexpected read response: %+v", readResp)
	}

	req = httptest.NewRequest(http.MethodPost, "/read-all", nil)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 read-all, got %d", rr.Code)
	}
	var readAllResp struct {
		MarkedRead  int `json:"marked_read"`
		UnreadCount int `json:"unread_count"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &readAllResp); err != nil {
		t.Fatalf("decode read-all response: %v body=%s", err, rr.Body.String())
	}
	if readAllResp.MarkedRead != 1 || readAllResp.UnreadCount != 0 {
		t.Fatalf("unexpected read-all response: %+v", readAllResp)
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
