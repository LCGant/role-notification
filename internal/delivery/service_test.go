package delivery

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

type stubSender struct {
	failToken string
	sent      []string
}

func (s *stubSender) SendVerification(ctx context.Context, to, token string) error {
	if token == s.failToken {
		return errors.New("forced failure")
	}
	s.sent = append(s.sent, "verify:"+token)
	return nil
}

func (s *stubSender) SendPasswordReset(ctx context.Context, to, token string) error {
	if token == s.failToken {
		return errors.New("forced failure")
	}
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
