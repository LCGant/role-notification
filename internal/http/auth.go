package http

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/LCGant/role-notification/internal/config"
	"github.com/LCGant/role-pep/pep"
)

var ErrUnauthorized = errors.New("unauthorized")

type viewer struct {
	UserID   int64
	TenantID string
}

type Authenticator interface {
	Required(context.Context, *http.Request) (viewer, error)
}

type sessionAuthenticator struct {
	introspector *pep.Introspector
	cookieName   string
	deviceCookie string
}

func newAuthenticator(cfg config.Config) (Authenticator, error) {
	if cfg.AuthBaseURL == "" || cfg.AuthInternalToken == "" {
		return nil, nil
	}
	introspector, err := pep.NewIntrospector(pep.IntrospectConfig{
		AuthBaseURL:       cfg.AuthBaseURL,
		InternalToken:     cfg.AuthInternalToken,
		CookieName:        cfg.SessionCookie,
		DeviceCookieName:  cfg.DeviceCookie,
		AllowInsecureHTTP: cfg.AllowInsecureHTTP,
	})
	if err != nil {
		return nil, err
	}
	return &sessionAuthenticator{
		introspector: introspector,
		cookieName:   cfg.SessionCookie,
		deviceCookie: cfg.DeviceCookie,
	}, nil
}

func (a *sessionAuthenticator) Required(ctx context.Context, r *http.Request) (viewer, error) {
	sessionToken, err := pep.ExtractSessionToken(r, a.cookieName)
	if err != nil {
		if errors.Is(err, pep.ErrUnauthenticated) {
			return viewer{}, ErrUnauthorized
		}
		return viewer{}, err
	}
	deviceToken := pep.ExtractDeviceToken(r, a.deviceCookie)
	subject, _, active, err := a.introspector.Introspect(ctx, sessionToken, deviceToken)
	if err != nil {
		if errors.Is(err, pep.ErrUnauthenticated) {
			return viewer{}, ErrUnauthorized
		}
		return viewer{}, err
	}
	if !active {
		return viewer{}, ErrUnauthorized
	}
	userID, err := strconv.ParseInt(strings.TrimSpace(subject.UserID), 10, 64)
	if err != nil || userID <= 0 {
		return viewer{}, ErrUnauthorized
	}
	return viewer{
		UserID:   userID,
		TenantID: strings.TrimSpace(subject.TenantID),
	}, nil
}
