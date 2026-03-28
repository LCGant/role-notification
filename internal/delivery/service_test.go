package delivery

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/LCGant/role-notification/internal/sender"
)

type stubSender struct {
	failToken string
	sent      []string
	mu        sync.Mutex
}

func (s *stubSender) SendVerification(ctx context.Context, to, token string) error {
	if token == s.failToken {
		return errors.New("forced failure")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent = append(s.sent, "verify:"+token)
	return nil
}

func (s *stubSender) SendPasswordReset(ctx context.Context, to, token string) error {
	if token == s.failToken {
		return errors.New("forced failure")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent = append(s.sent, "reset:"+token)
	return nil
}

func (s *stubSender) SendSocial(ctx context.Context, to, subject, body string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent = append(s.sent, "social:"+subject)
	return nil
}

func TestQueuePayloadIsEncryptedAtRest(t *testing.T) {
	dir := t.TempDir()
	key := bytes.Repeat([]byte{7}, 32)
	svc := newTestQueueService(dir, key, &stubSender{})

	if err := svc.EnqueueVerification(context.Background(), "u@example.com", "super-secret-token"); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 1 {
		t.Fatalf("expected one queue file, got %d err=%v", len(files), err)
	}
	payload, err := os.ReadFile(filepath.Join(dir, files[0].Name()))
	if err != nil {
		t.Fatalf("read payload: %v", err)
	}
	if bytes.Contains(payload, []byte("super-secret-token")) {
		t.Fatalf("expected queue payload to be encrypted at rest")
	}
}

func TestProcessPendingContinuesAfterFailedJob(t *testing.T) {
	dir := t.TempDir()
	key := bytes.Repeat([]byte{9}, 32)
	backend := &stubSender{failToken: "bad-token"}
	svc := newTestQueueService(dir, key, backend)

	if err := svc.EnqueueVerification(context.Background(), "bad@example.com", "bad-token"); err != nil {
		t.Fatalf("enqueue bad: %v", err)
	}
	if err := svc.EnqueueVerification(context.Background(), "good@example.com", "good-token"); err != nil {
		t.Fatalf("enqueue good: %v", err)
	}

	svc.processPending(context.Background())

	if len(backend.sent) != 1 || backend.sent[0] != "verify:good-token" {
		t.Fatalf("expected good job to be delivered despite prior failure, got %#v", backend.sent)
	}
}

type blockingSender struct {
	started chan struct{}
	release chan struct{}
	mu      sync.Mutex
	sent    []string
}

func (s *blockingSender) SendVerification(ctx context.Context, to, token string) error {
	select {
	case s.started <- struct{}{}:
	default:
	}
	<-s.release
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent = append(s.sent, "verify:"+token)
	return nil
}

func (s *blockingSender) SendPasswordReset(ctx context.Context, to, token string) error {
	return errors.New("unexpected password reset dispatch")
}

func (s *blockingSender) SendSocial(ctx context.Context, to, subject, body string) error {
	return errors.New("unexpected social dispatch")
}

func TestProcessPendingClaimsJobsAtomically(t *testing.T) {
	dir := t.TempDir()
	key := bytes.Repeat([]byte{4}, 32)
	backend := &blockingSender{
		started: make(chan struct{}, 2),
		release: make(chan struct{}),
	}
	svcA := newTestQueueService(dir, key, backend)
	svcB := newTestQueueService(dir, key, backend)

	if err := svcA.EnqueueVerification(context.Background(), "user@example.com", "job-token"); err != nil {
		t.Fatalf("enqueue job: %v", err)
	}

	done := make(chan struct{}, 2)
	go func() {
		svcA.processPending(context.Background())
		done <- struct{}{}
	}()

	select {
	case <-backend.started:
	case <-time.After(2 * time.Second):
		t.Fatal("expected first worker to start dispatch")
	}

	go func() {
		svcB.processPending(context.Background())
		done <- struct{}{}
	}()

	time.Sleep(100 * time.Millisecond)
	close(backend.release)

	for i := 0; i < 2; i++ {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("expected workers to finish")
		}
	}

	backend.mu.Lock()
	defer backend.mu.Unlock()
	if len(backend.sent) != 1 || backend.sent[0] != "verify:job-token" {
		t.Fatalf("expected single delivery, got %#v", backend.sent)
	}
}

func TestQueueKeyDerivationIsDeterministic(t *testing.T) {
	rawKey := bytes.Repeat([]byte{5}, 32)
	keyA, err := deriveQueueKey(rawKey)
	if err != nil {
		t.Fatalf("derive key A: %v", err)
	}
	keyB, err := deriveQueueKey(rawKey)
	if err != nil {
		t.Fatalf("derive key B: %v", err)
	}
	if !bytes.Equal(keyA, keyB) {
		t.Fatalf("expected deterministic queue key derivation")
	}
	if bytes.Equal(keyA, rawKey) {
		t.Fatalf("expected derived queue key to differ from raw secret")
	}
}

func TestQueueSupportsVersionedKeyRotation(t *testing.T) {
	dir := t.TempDir()
	backend := &stubSender{}

	legacy := newTestQueueService(dir, bytes.Repeat([]byte{1}, 32), backend)
	if err := legacy.EnqueueVerification(context.Background(), "u@example.com", "legacy-token"); err != nil {
		t.Fatalf("enqueue legacy: %v", err)
	}
	time.Sleep(time.Millisecond)

	rotated := NewWithKeyring(dir, "v2", map[string][]byte{
		"v1": bytes.Repeat([]byte{1}, 32),
		"v2": bytes.Repeat([]byte{2}, 32),
	}, false, backend, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := rotated.EnqueueVerification(context.Background(), "u@example.com", "new-token"); err != nil {
		t.Fatalf("enqueue new: %v", err)
	}

	rotated.processPending(context.Background())

	backend.mu.Lock()
	defer backend.mu.Unlock()
	if len(backend.sent) != 2 {
		t.Fatalf("expected both legacy and rotated jobs to be delivered, got %#v", backend.sent)
	}
}

func TestEnsureSecureDirAllowsRelaxedPermsWhenConfigured(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Skipf("chmod not supported: %v", err)
	}
	if err := ensureSecureDir(dir, false); err != nil {
		t.Fatalf("expected relaxed permission check to pass, got %v", err)
	}
}

func newTestQueueService(dir string, key []byte, backend sender.Sender) *Service {
	return NewWithKeyring(dir, "v1", map[string][]byte{"v1": key}, false, backend, slog.New(slog.NewTextHandler(io.Discard, nil)))
}
