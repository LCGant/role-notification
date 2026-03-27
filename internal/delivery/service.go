package delivery

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/LCGant/role-notification/internal/sender"
	"golang.org/x/crypto/hkdf"
)

type Kind string

const (
	KindVerification  Kind = "verification"
	KindPasswordReset Kind = "password_reset"
	KindSocial        Kind = "social"
)

type Job struct {
	Kind          Kind      `json:"kind"`
	To            string    `json:"to"`
	Token         string    `json:"token"`
	Subject       string    `json:"subject,omitempty"`
	Body          string    `json:"body,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	Attempts      int       `json:"attempts,omitempty"`
	NextAttemptAt time.Time `json:"next_attempt_at,omitempty"`
}

type Service struct {
	queueDir         string
	queueKeys        map[string][]byte
	activeKeyVersion string
	legacyKeyVersion string
	sender           sender.Sender
	logger           *slog.Logger
}

type envelope struct {
	KeyVersion string `json:"key_version,omitempty"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

func New(queueDir string, queueKey []byte, backend sender.Sender, logger *slog.Logger) *Service {
	return NewWithKeyring(queueDir, "v1", map[string][]byte{"v1": queueKey}, backend, logger)
}

func NewWithKeyring(queueDir, activeKeyVersion string, queueKeys map[string][]byte, backend sender.Sender, logger *slog.Logger) *Service {
	derivedKeys := map[string][]byte{}
	for version, rawKey := range queueKeys {
		version = strings.TrimSpace(version)
		if version == "" || len(rawKey) == 0 {
			continue
		}
		derived, err := deriveQueueKey(rawKey)
		if err != nil {
			panic(err)
		}
		derivedKeys[version] = derived
	}
	activeKeyVersion = strings.TrimSpace(activeKeyVersion)
	if activeKeyVersion == "" {
		activeKeyVersion = "v1"
	}
	legacyKeyVersion := "v1"
	if _, ok := derivedKeys[legacyKeyVersion]; !ok {
		legacyKeyVersion = activeKeyVersion
	}
	return &Service{
		queueDir:         queueDir,
		queueKeys:        derivedKeys,
		activeKeyVersion: activeKeyVersion,
		legacyKeyVersion: legacyKeyVersion,
		sender:           backend,
		logger:           logger,
	}
}

func (s *Service) EnqueueVerification(ctx context.Context, to, token string) error {
	return s.enqueue(ctx, Job{
		Kind:      KindVerification,
		To:        strings.TrimSpace(to),
		Token:     strings.TrimSpace(token),
		CreatedAt: time.Now().UTC(),
	})
}

func (s *Service) EnqueuePasswordReset(ctx context.Context, to, token string) error {
	return s.enqueue(ctx, Job{
		Kind:      KindPasswordReset,
		To:        strings.TrimSpace(to),
		Token:     strings.TrimSpace(token),
		CreatedAt: time.Now().UTC(),
	})
}

func (s *Service) EnqueueSocial(ctx context.Context, to, subject, body string) error {
	return s.enqueue(ctx, Job{
		Kind:      KindSocial,
		To:        strings.TrimSpace(to),
		Subject:   strings.TrimSpace(subject),
		Body:      strings.TrimSpace(body),
		CreatedAt: time.Now().UTC(),
	})
}

func (s *Service) enqueue(ctx context.Context, job Job) error {
	_ = ctx
	if err := os.MkdirAll(s.queueDir, 0o700); err != nil {
		return err
	}
	payload, err := s.encryptJob(job)
	if err != nil {
		return err
	}
	name := fmt.Sprintf("%d-%s.json", time.Now().UTC().UnixNano(), job.Kind)
	return os.WriteFile(filepath.Join(s.queueDir, name), payload, 0o600)
}

func (s *Service) Run(ctx context.Context) {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	s.processPending(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.processPending(ctx)
		}
	}
}

func (s *Service) processPending(ctx context.Context) {
	if err := os.MkdirAll(s.queueDir, 0o700); err != nil {
		if s.logger != nil {
			s.logger.Error("notification queue init failed", "err", err)
		}
		return
	}
	if err := os.MkdirAll(s.processingDir(), 0o700); err != nil {
		if s.logger != nil {
			s.logger.Error("notification processing queue init failed", "err", err)
		}
		return
	}
	entries, err := os.ReadDir(s.queueDir)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("notification queue read failed", "err", err)
		}
		return
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(s.queueDir, entry.Name())
		claimedPath, err := s.claim(path)
		if err != nil {
			continue
		}
		payload, err := os.ReadFile(claimedPath)
		if err != nil {
			_ = os.Remove(claimedPath)
			continue
		}
		var job Job
		if err := s.decryptJob(payload, &job); err != nil {
			_ = os.Remove(claimedPath)
			continue
		}
		if !job.NextAttemptAt.IsZero() && job.NextAttemptAt.After(time.Now().UTC()) {
			_ = s.release(claimedPath)
			continue
		}
		if err := s.dispatch(ctx, job); err != nil {
			if s.logger != nil {
				s.logger.Warn("notification dispatch failed", "kind", job.Kind, "to", job.To, "attempts", job.Attempts+1, "err", err)
			}
			if requeueErr := s.requeue(claimedPath, job); requeueErr != nil && s.logger != nil {
				s.logger.Error("notification requeue failed", "kind", job.Kind, "to", job.To, "err", requeueErr)
			}
			continue
		}
		_ = os.Remove(claimedPath)
	}
}

func (s *Service) dispatch(ctx context.Context, job Job) error {
	switch job.Kind {
	case KindVerification:
		return s.sender.SendVerification(ctx, job.To, job.Token)
	case KindPasswordReset:
		return s.sender.SendPasswordReset(ctx, job.To, job.Token)
	case KindSocial:
		return s.sender.SendSocial(ctx, job.To, job.Subject, job.Body)
	default:
		return fmt.Errorf("unsupported notification kind %q", job.Kind)
	}
}

func (s *Service) requeue(path string, job Job) error {
	job.Attempts++
	if job.Attempts >= 5 {
		return s.deadLetter(path)
	}
	job.NextAttemptAt = time.Now().UTC().Add(backoffForAttempt(job.Attempts))
	payload, err := s.encryptJob(job)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		return err
	}
	return s.release(path)
}

func (s *Service) deadLetter(path string) error {
	deadDir := filepath.Join(s.queueDir, "dead-letter")
	if err := os.MkdirAll(deadDir, 0o700); err != nil {
		return err
	}
	return os.Rename(path, filepath.Join(deadDir, filepath.Base(path)))
}

func (s *Service) processingDir() string {
	return filepath.Join(s.queueDir, "processing")
}

func (s *Service) claim(path string) (string, error) {
	claimedPath := filepath.Join(s.processingDir(), filepath.Base(path))
	if err := os.Rename(path, claimedPath); err != nil {
		return "", err
	}
	return claimedPath, nil
}

func (s *Service) release(path string) error {
	return os.Rename(path, filepath.Join(s.queueDir, filepath.Base(path)))
}

func (s *Service) encryptJob(job Job) ([]byte, error) {
	plain, err := json.Marshal(job)
	if err != nil {
		return nil, err
	}
	queueKey, err := s.queueKeyForVersion(s.activeKeyVersion)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(queueKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	sealed := gcm.Seal(nil, nonce, plain, nil)
	return json.Marshal(envelope{
		KeyVersion: s.activeKeyVersion,
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(sealed),
	})
}

func (s *Service) decryptJob(payload []byte, job *Job) error {
	var env envelope
	if err := json.Unmarshal(payload, &env); err != nil {
		return err
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return err
	}
	keyVersion := strings.TrimSpace(env.KeyVersion)
	if keyVersion == "" {
		keyVersion = s.legacyKeyVersion
	}
	queueKey, err := s.queueKeyForVersion(keyVersion)
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(queueKey)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}
	return json.Unmarshal(plain, job)
}

func (s *Service) queueKeyForVersion(version string) ([]byte, error) {
	version = strings.TrimSpace(version)
	if version == "" {
		return nil, fmt.Errorf("queue key version is required")
	}
	key, ok := s.queueKeys[version]
	if !ok || len(key) == 0 {
		return nil, fmt.Errorf("queue key version %q is not configured", version)
	}
	return key, nil
}

func deriveQueueKey(secret []byte) ([]byte, error) {
	reader := hkdf.New(sha256.New, secret, []byte("role-notification-queue"), []byte("notification-queue-v1"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

func backoffForAttempt(attempt int) time.Duration {
	if attempt <= 0 {
		return time.Second
	}
	backoff := time.Second << min(attempt-1, 5)
	if backoff > time.Minute {
		return time.Minute
	}
	return backoff
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
