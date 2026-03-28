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
	"time"

	internaltoken "github.com/LCGant/role-internaltoken"
)

const (
	introspectScope = "auth:sessions:introspect"
	userLookupScope = "auth:users:read"
)

type Client struct {
	baseURL    string
	httpClient *http.Client
	minter     *internaltoken.MintClient
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

func New(baseURL, mintToken string) *Client {
	if strings.TrimSpace(baseURL) == "" || strings.TrimSpace(mintToken) == "" {
		return nil
	}
	httpClient := &http.Client{Timeout: 5 * time.Second}
	client := &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: httpClient,
		minter: &internaltoken.MintClient{
			BaseURL:       strings.TrimRight(baseURL, "/"),
			InternalToken: strings.TrimSpace(mintToken),
			HTTPClient:    httpClient,
		},
	}
	client.minter.Do = client.doWithRetry
	return client
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

	resp, err := c.doWithRetry(req)
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

	resp, err := c.doWithRetry(req)
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
	if scope == "" || c.minter == nil {
		return "", nil
	}
	token, _, err := c.minter.Mint(ctx, internaltoken.MintRequest{
		Audience: "auth",
		Scope:    scope,
	})
	if err != nil {
		return "", err
	}
	return token, nil
}

func (c *Client) doWithRetry(req *http.Request) (*http.Response, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		cloned := req.Clone(req.Context())
		resp, err := c.httpClient.Do(cloned)
		if err == nil && !shouldRetryStatus(resp.StatusCode) {
			return resp, nil
		}
		if err == nil {
			lastErr = fmt.Errorf("auth returned %d", resp.StatusCode)
			resp.Body.Close()
		} else {
			lastErr = err
		}
		if attempt == 2 {
			break
		}
		select {
		case <-req.Context().Done():
			return nil, req.Context().Err()
		case <-time.After(time.Duration(50*(1<<attempt)) * time.Millisecond):
		}
	}
	return nil, lastErr
}

func shouldRetryStatus(status int) bool {
	return status == http.StatusBadGateway || status == http.StatusServiceUnavailable || status == http.StatusGatewayTimeout
}
