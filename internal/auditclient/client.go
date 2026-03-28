package auditclient

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	httpclient "github.com/LCGant/role-httpclient"
	internaltoken "github.com/LCGant/role-internaltoken"
	"github.com/LCGant/role-notification/internal/config"
)

type Client struct {
	client *httpclient.Client
	minter *internaltoken.MintClient
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

func New(cfg config.Config) *Client {
	if strings.TrimSpace(cfg.AuditBaseURL) == "" || strings.TrimSpace(cfg.AuthBaseURL) == "" || strings.TrimSpace(cfg.AuthServiceTokenMintToken) == "" {
		return nil
	}
	httpClient := &http.Client{Timeout: cfg.AuditTimeout}
	if httpClient.Timeout <= 0 {
		httpClient.Timeout = 5 * time.Second
	}
	client := &Client{
		minter: &internaltoken.MintClient{
			BaseURL:       strings.TrimRight(cfg.AuthBaseURL, "/"),
			InternalToken: strings.TrimSpace(cfg.AuthServiceTokenMintToken),
			HTTPClient:    httpClient,
		},
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
	if c == nil || c.minter == nil {
		return "", nil
	}
	token, _, err := c.minter.Mint(ctx, internaltoken.MintRequest{
		Audience: "audit",
		Scope:    "audit:events:write",
	})
	if err != nil {
		return "", err
	}
	return token, nil
}
