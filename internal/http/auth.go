package http

import (
	"context"
	"errors"
	"net/http"
	"strings"

	apperrors "github.com/LCGant/role-errors"
	"github.com/LCGant/role-notification/internal/authclient"
	"github.com/LCGant/role-notification/internal/config"
)

var ErrUnauthorized = apperrors.ErrUnauthorized

type viewer struct {
	UserID   int64
	TenantID string
}

type Authenticator interface {
	Required(context.Context, *http.Request) (viewer, error)
}

type sessionAuthenticator struct {
	auth         *authclient.Client
	cookieName   string
	deviceCookie string
}

func newAuthenticator(cfg config.Config) (Authenticator, error) {
	if cfg.AuthBaseURL == "" || cfg.AuthServiceTokenMintToken == "" {
		return nil, nil
	}
	client := authclient.New(cfg.AuthBaseURL, cfg.AuthServiceTokenMintToken)
	if client == nil {
		return nil, nil
	}
	return &sessionAuthenticator{
		auth:         client,
		cookieName:   cfg.SessionCookie,
		deviceCookie: cfg.DeviceCookie,
	}, nil
}

func (a *sessionAuthenticator) Required(ctx context.Context, r *http.Request) (viewer, error) {
	sessionToken, err := extractCookieValue(r, a.cookieName)
	if err != nil {
		if errors.Is(err, ErrUnauthorized) {
			return viewer{}, ErrUnauthorized
		}
		return viewer{}, err
	}
	deviceToken, _ := extractCookieValue(r, a.deviceCookie)
	subject, active, err := a.auth.Introspect(ctx, sessionToken, deviceToken)
	if err != nil {
		return viewer{}, err
	}
	if !active || subject == nil {
		return viewer{}, ErrUnauthorized
	}
	if subject.UserID <= 0 {
		return viewer{}, ErrUnauthorized
	}
	return viewer{
		UserID:   subject.UserID,
		TenantID: strings.TrimSpace(subject.TenantID),
	}, nil
}

func extractCookieValue(r *http.Request, name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", ErrUnauthorized
	}
	cookie, err := r.Cookie(name)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return "", ErrUnauthorized
	}
	return strings.TrimSpace(cookie.Value), nil
}
