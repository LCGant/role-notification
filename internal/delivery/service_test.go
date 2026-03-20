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

func TestQueuePayloadIsEncryptedAtRest(t *testing.T) {
	dir := t.TempDir()
	key := bytes.Repeat([]byte{7}, 32)
	svc := New(dir, key, &stubSender{}, slog.New(slog.NewTextHandler(io.Discard, nil)))

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
	svc := New(dir, key, backend, slog.New(slog.NewTextHandler(io.Discard, nil)))

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

func TestProcessPendingClaimsJobsAtomically(t *testing.T) {
	dir := t.TempDir()
	key := bytes.Repeat([]byte{4}, 32)
	backend := &blockingSender{
		started: make(chan struct{}, 2),
		release: make(chan struct{}),
	}
	svcA := New(dir, key, backend, slog.New(slog.NewTextHandler(io.Discard, nil)))
	svcB := New(dir, key, backend, slog.New(slog.NewTextHandler(io.Discard, nil)))

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
