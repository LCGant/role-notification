package authclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	introspectScope = "auth:sessions:introspect"
	userLookupScope = "auth:users:read"
)

type Client struct {
	baseURL    string
	mintToken  string
	httpClient *http.Client
	mu         sync.Mutex
	tokenCache map[string]cachedToken
}

type User struct {
	ID       int64  `json:"id"`
	TenantID string `json:"tenant_id"`
	Email    string `json:"email"`
}

type Subject struct {
	UserID   int64  `json:"user_id"`
	TenantID string `json:"tenant_id"`
	AAL      int    `json:"aal"`
	AuthTime string `json:"auth_time"`
}

type userResponse struct {
	User *User `json:"user,omitempty"`
}

type introspectResponse struct {
	Active  bool            `json:"active"`
	Subject *Subject        `json:"subject,omitempty"`
	Session json.RawMessage `json:"session,omitempty"`
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

type cachedToken struct {
	value     string
	expiresAt time.Time
}

func New(baseURL, mintToken string) *Client {
	if strings.TrimSpace(baseURL) == "" || strings.TrimSpace(mintToken) == "" {
		return nil
	}
	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		mintToken:  strings.TrimSpace(mintToken),
		httpClient: &http.Client{Timeout: 5 * time.Second},
		tokenCache: map[string]cachedToken{},
	}
}

func (c *Client) LookupUser(ctx context.Context, userID int64, tenantID string) (*User, error) {
	if c == nil || userID <= 0 || strings.TrimSpace(tenantID) == "" {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	token, err := c.bearerToken(ctx, userLookupScope)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/internal/users/"+url.PathEscape(strconv.FormatInt(userID, 10)), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Tenant-Id", strings.TrimSpace(tenantID))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, nil
	default:
		return nil, fmt.Errorf("auth returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(body) > 1<<20 {
		return nil, errors.New("auth response too large")
	}
	var out userResponse
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return nil, err
	}
	return out.User, nil
}

func (c *Client) Introspect(ctx context.Context, sessionToken, deviceToken string) (*Subject, bool, error) {
	if c == nil {
		return nil, false, nil
	}
	sessionToken = strings.TrimSpace(sessionToken)
	if sessionToken == "" {
		return nil, false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	token, err := c.bearerToken(ctx, introspectScope)
	if err != nil {
		return nil, false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/internal/sessions/introspect", nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Session-Token", sessionToken)
	if strings.TrimSpace(deviceToken) != "" {
		req.Header.Set("X-Device-Token", strings.TrimSpace(deviceToken))
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusUnauthorized {
		return nil, false, fmt.Errorf("auth returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil {
		return nil, false, err
	}
	if len(body) > 1<<20 {
		return nil, false, errors.New("auth response too large")
	}
	var out introspectResponse
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return nil, false, err
	}
	if !out.Active || out.Subject == nil {
		return nil, false, nil
	}
	return out.Subject, true, nil
}

func (c *Client) bearerToken(ctx context.Context, scope string) (string, error) {
	scope = strings.TrimSpace(scope)
	if scope == "" || c.mintToken == "" || c.baseURL == "" {
		return "", nil
	}
	token, _, err := c.mintAuthToken(ctx, scope)
	if err != nil {
		return "", err
	}
	return token, nil
}

func (c *Client) mintAuthToken(ctx context.Context, scope string) (string, time.Time, error) {
	payload, err := json.Marshal(serviceTokenMintRequest{
		Audience: "auth",
		Scope:    scope,
	})
	if err != nil {
		return "", time.Time{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/internal/service-tokens", bytes.NewReader(payload))
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
