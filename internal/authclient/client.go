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
)

type Client struct {
	baseURL       string
	internalToken string
	httpClient    *http.Client
}

type User struct {
	ID       int64  `json:"id"`
	TenantID string `json:"tenant_id"`
	Email    string `json:"email"`
}

type userResponse struct {
	User *User `json:"user,omitempty"`
}

func New(baseURL, internalToken string) *Client {
	if strings.TrimSpace(baseURL) == "" || strings.TrimSpace(internalToken) == "" {
		return nil
	}
	return &Client{
		baseURL:       strings.TrimRight(baseURL, "/"),
		internalToken: strings.TrimSpace(internalToken),
		httpClient:    &http.Client{Timeout: 5 * time.Second},
	}
}

func (c *Client) LookupUser(ctx context.Context, userID int64, tenantID string) (*User, error) {
	if c == nil || userID <= 0 {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/internal/users/"+url.PathEscape(strconv.FormatInt(userID, 10)), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Internal-Token", c.internalToken)
	if strings.TrimSpace(tenantID) != "" {
		req.Header.Set("X-Tenant-Id", strings.TrimSpace(tenantID))
	}

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
