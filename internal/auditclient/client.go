package auditclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	httpclient "github.com/LCGant/role-httpclient"
	"github.com/LCGant/role-notification/internal/config"
)

type Client struct {
	client      *httpclient.Client
	authBaseURL string
	mintToken   string
	httpClient  *http.Client
	mu          sync.Mutex
}

type Event struct {
	Source    string         `json:"source"`
	EventType string         `json:"event_type"`
	UserID    *int64         `json:"user_id,omitempty"`
	TenantID  string         `json:"tenant_id,omitempty"`
	Success   bool           `json:"success"`
	Metadata  map[string]any `json:"metadata,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
}

type serviceTokenMintRequest struct {
	Audience string `json:"audience"`
	Scope    string `json:"scope"`
	TenantID string `json:"tenant_id,omitempty"`
}

type serviceTokenMintResponse struct {
	Token *serviceTokenPayload `json:"token,omitempty"`
}

type serviceTokenPayload struct {
	Value     string `json:"value"`
	ExpiresAt string `json:"expires_at"`
}

func New(cfg config.Config) *Client {
	if strings.TrimSpace(cfg.AuditBaseURL) == "" || strings.TrimSpace(cfg.AuthBaseURL) == "" || strings.TrimSpace(cfg.AuthServiceTokenMintToken) == "" {
		return nil
	}
	client := &Client{
		authBaseURL: strings.TrimRight(cfg.AuthBaseURL, "/"),
		mintToken:   strings.TrimSpace(cfg.AuthServiceTokenMintToken),
		httpClient:  &http.Client{Timeout: cfg.AuditTimeout},
	}
	if client.httpClient.Timeout <= 0 {
		client.httpClient.Timeout = 5 * time.Second
	}
	client.client = httpclient.New(httpclient.Config{
		BaseURL: strings.TrimRight(cfg.AuditBaseURL, "/"),
		BearerToken: func(ctx context.Context) (string, error) {
			return client.bearerToken(ctx)
		},
		Timeout:      cfg.AuditTimeout,
		MaxRetries:   3,
		RetryBackoff: 100 * time.Millisecond,
		QueueSize:    128,
		SpoolDir:     strings.TrimSpace(cfg.AuditSpoolDir),
		DefaultPath:  "/internal/events",
		Logger:       slog.Default(),
	})
	return client
}

func (c *Client) Record(ctx context.Context, event Event) error {
	if c == nil {
		return nil
	}
	c.client.PostAsync(event)
	return nil
}

func (c *Client) bearerToken(ctx context.Context) (string, error) {
	token, _, err := c.mintAuditToken(ctx)
	if err != nil {
		return "", err
	}
	return token, nil
}

func (c *Client) mintAuditToken(ctx context.Context) (string, time.Time, error) {
	payload, err := json.Marshal(serviceTokenMintRequest{
		Audience: "audit",
		Scope:    "audit:events:write",
	})
	if err != nil {
		return "", time.Time{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.authBaseURL+"/internal/service-tokens", bytes.NewReader(payload))
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Token", c.mintToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", time.Time{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", time.Time{}, fmt.Errorf("service token mint returned %d", resp.StatusCode)
	}
	var out serviceTokenMintResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", time.Time{}, err
	}
	if out.Token == nil || strings.TrimSpace(out.Token.Value) == "" || strings.TrimSpace(out.Token.ExpiresAt) == "" {
		return "", time.Time{}, fmt.Errorf("service token mint returned invalid payload")
	}
	expiresAt, err := time.Parse(time.RFC3339, strings.TrimSpace(out.Token.ExpiresAt))
	if err != nil {
		return "", time.Time{}, err
	}
	return strings.TrimSpace(out.Token.Value), expiresAt, nil
}
