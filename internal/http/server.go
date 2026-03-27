package http

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"expvar"
	"html"
	"log/slog"
	nethttp "net/http"
	"net/mail"
	"strconv"
	"strings"
	"time"
	"unicode"

	libcrypto "github.com/LCGant/role-crypto"
	"github.com/LCGant/role-httpx"
	internaltoken "github.com/LCGant/role-internaltoken"
	"github.com/LCGant/role-notification/internal/authclient"
	"github.com/LCGant/role-notification/internal/config"
	"github.com/LCGant/role-notification/internal/delivery"
	basestore "github.com/LCGant/role-notification/internal/store"
	"github.com/LCGant/role-notification/internal/store/memory"
	ratelimit "github.com/LCGant/role-ratelimit"
)

type Server struct {
	cfg         config.Config
	logger      *slog.Logger
	deliverer   *delivery.Service
	inbox       basestore.InboxStore
	authn       Authenticator
	authUsers   *authclient.Client
	mux         *nethttp.ServeMux
	serviceJWT  *internaltoken.Verifier
	mailLimiter ratelimit.Limiter
}

type deliveryRequest struct {
	To    string `json:"to"`
	Token string `json:"token"`
}

type socialDeliveryRequest struct {
	UserID   int64  `json:"user_id"`
	TenantID string `json:"tenant_id"`
	To       string `json:"to,omitempty"`
	Kind     string `json:"kind"`
	Subject  string `json:"subject"`
	Body     string `json:"body"`
}

type notificationResponse struct {
	ID        string     `json:"id"`
	Kind      string     `json:"kind"`
	KindLabel string     `json:"kind_label"`
	KindGroup string     `json:"kind_group"`
	Subject   string     `json:"subject"`
	Body      string     `json:"body"`
	CreatedAt time.Time  `json:"created_at"`
	ReadAt    *time.Time `json:"read_at,omitempty"`
	IsRead    bool       `json:"is_read"`
}

type notificationListResponse struct {
	Notifications []notificationResponse `json:"notifications"`
	Total         int                    `json:"total"`
	UnreadCount   int                    `json:"unread_count"`
	Limit         int                    `json:"limit"`
	Offset        int                    `json:"offset"`
	HasMore       bool                   `json:"has_more"`
	NextOffset    *int                   `json:"next_offset,omitempty"`
}

type internalSocialClaims struct {
	Subject  string
	Scope    string
	TenantID string
}

type internalSocialClaimsKey struct{}

func New(cfg config.Config, logger *slog.Logger, svc *delivery.Service, inbox basestore.InboxStore) nethttp.Handler {
	authn, err := newAuthenticator(cfg)
	if err != nil {
		panic(err)
	}
	return NewWithDependencies(cfg, logger, svc, inbox, authn, authclient.New(cfg.AuthBaseURL, cfg.AuthServiceTokenMintToken))
}

func NewWithDependencies(cfg config.Config, logger *slog.Logger, svc *delivery.Service, inbox basestore.InboxStore, authn Authenticator, users *authclient.Client) nethttp.Handler {
	if inbox == nil {
		inbox = memory.New()
	}
	s := &Server{
		cfg:       cfg,
		logger:    logger,
		deliverer: svc,
		inbox:     inbox,
		authn:     authn,
		authUsers: users,
		mux:       nethttp.NewServeMux(),
		mailLimiter: ratelimit.Counter(ratelimit.CounterConfig{
			Requests: 5,
			Window:   time.Hour,
		}),
	}
	if len(cfg.ServiceTokenPublicKeys) > 0 {
		var verifierOpts []internaltoken.VerifierOption
		if cfg.ServiceTokenReplayRedisURL != "" {
			replayGuard, err := internaltoken.NewRedisReplayGuard(cfg.ServiceTokenReplayRedisURL, "notification:internaltoken:jti:")
			if err != nil {
				panic(err)
			}
			verifierOpts = append(verifierOpts, internaltoken.WithReplayGuard(replayGuard))
		}
		verifier, err := internaltoken.NewVerifier(cfg.ServiceTokenIssuer, cfg.ServiceTokenPublicKeys, 15*time.Second, verifierOpts...)
		if err != nil {
			panic(err)
		}
		s.serviceJWT = verifier
	}
	s.routes()
	return s
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Header().Set("Cache-Control", "no-store")
		httpx.WriteJSON(w, nethttp.StatusOK, map[string]string{"status": "ok"})
	})
	s.mux.Handle("/metrics", s.metricsGuard(expvar.Handler()))
	s.mux.Handle("POST /internal/email-verification", s.internalWithToken(s.cfg.VerificationInternalToken, s.handleVerification))
	s.mux.Handle("POST /internal/password-reset", s.internalWithToken(s.cfg.PasswordResetInternalToken, s.handlePasswordReset))
	s.mux.Handle("POST /internal/social", s.internalSocialAuth(s.handleSocial))
	s.mux.Handle("GET /{$}", s.authenticated(s.handleListNotifications))
	s.mux.Handle("GET /unread-count", s.authenticated(s.handleUnreadCount))
	s.mux.Handle("POST /read-all", s.authenticated(s.handleReadAllNotifications))
	s.mux.Handle("POST /{id}/read", s.authenticated(s.handleReadNotification))
}

func (s *Server) ServeHTTP(w nethttp.ResponseWriter, r *nethttp.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) internalWithToken(token string, next nethttp.HandlerFunc) nethttp.Handler {
	return nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if !libcrypto.ConstantTimeEqual(strings.TrimSpace(r.Header.Get("X-Internal-Token")), token) {
			httpx.WriteError(w, nethttp.StatusUnauthorized, "unauthorized")
			return
		}
		next(w, r)
	})
}

func (s *Server) metricsGuard(next nethttp.Handler) nethttp.Handler {
	return nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if s.cfg.MetricsToken == "" {
			httpx.WriteError(w, nethttp.StatusForbidden, "forbidden")
			return
		}
		if !libcrypto.ConstantTimeEqual(strings.TrimSpace(r.Header.Get("X-Metrics-Token")), s.cfg.MetricsToken) {
			httpx.WriteError(w, nethttp.StatusForbidden, "forbidden")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) internalSocialAuth(next nethttp.HandlerFunc) nethttp.Handler {
	return nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		authz := strings.TrimSpace(r.Header.Get("Authorization"))
		if strings.HasPrefix(authz, "Bearer ") {
			claims, ok := s.verifySocialBearerToken(w, r)
			if !ok {
				return
			}
			ctx := context.WithValue(r.Context(), internalSocialClaimsKey{}, claims)
			next(w, r.WithContext(ctx))
			return
		}
		httpx.WriteError(w, nethttp.StatusUnauthorized, "unauthorized")
	})
}

func (s *Server) verifySocialBearerToken(w nethttp.ResponseWriter, r *nethttp.Request) (internalSocialClaims, bool) {
	authz := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(authz, "Bearer ") {
		return internalSocialClaims{}, false
	}
	if s.serviceJWT == nil {
		httpx.WriteError(w, nethttp.StatusServiceUnavailable, "auth_unavailable")
		return internalSocialClaims{}, false
	}
	token := strings.TrimSpace(strings.TrimPrefix(authz, "Bearer "))
	claims, err := s.serviceJWT.Verify(token, s.cfg.ServiceTokenAudience)
	if err != nil {
		httpx.WriteError(w, nethttp.StatusUnauthorized, "unauthorized")
		return internalSocialClaims{}, false
	}
	if claims.Subject != "social" || claims.Scope != "notifications:social:write" {
		httpx.WriteError(w, nethttp.StatusForbidden, "forbidden")
		return internalSocialClaims{}, false
	}
	return internalSocialClaims{
		Subject:  claims.Subject,
		Scope:    claims.Scope,
		TenantID: claims.TenantID,
	}, true
}

func (s *Server) handleVerification(w nethttp.ResponseWriter, r *nethttp.Request) {
	var req deliveryRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, nethttp.StatusBadRequest, "bad_request")
		return
	}
	req.To = strings.TrimSpace(req.To)
	req.Token = strings.TrimSpace(req.Token)
	if req.To == "" || req.Token == "" {
		httpx.WriteError(w, nethttp.StatusBadRequest, "bad_request")
		return
	}
	normalizedTo, err := normalizeEmailAddress(req.To)
	if err != nil {
		httpx.WriteError(w, nethttp.StatusBadRequest, "bad_request")
		return
	}
	if s.mailLimiter != nil && !s.mailLimiter.Allow(internalMailRateLimitKey("verify", normalizedTo, strings.TrimSpace(r.Header.Get("X-Internal-Token")))) {
		httpx.WriteError(w, nethttp.StatusTooManyRequests, "rate_limit_exceeded")
		return
	}
	if err := s.deliverer.EnqueueVerification(r.Context(), normalizedTo, req.Token); err != nil {
		s.logger.Error("enqueue verification failed", "err", err)
		httpx.WriteError(w, nethttp.StatusBadGateway, "delivery_failed")
		return
	}
	httpx.WriteJSON(w, nethttp.StatusAccepted, map[string]string{"status": "queued"})
}

func (s *Server) handlePasswordReset(w nethttp.ResponseWriter, r *nethttp.Request) {
	var req deliveryRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, nethttp.StatusBadRequest, "bad_request")
		return
	}
	req.To = strings.TrimSpace(req.To)
	req.Token = strings.TrimSpace(req.Token)
	if req.To == "" || req.Token == "" {
		httpx.WriteError(w, nethttp.StatusBadRequest, "bad_request")
		return
	}
	normalizedTo, err := normalizeEmailAddress(req.To)
	if err != nil {
		httpx.WriteError(w, nethttp.StatusBadRequest, "bad_request")
		return
	}
	if s.mailLimiter != nil && !s.mailLimiter.Allow(internalMailRateLimitKey("reset", normalizedTo, strings.TrimSpace(r.Header.Get("X-Internal-Token")))) {
		httpx.WriteError(w, nethttp.StatusTooManyRequests, "rate_limit_exceeded")
		return
	}
	if err := s.deliverer.EnqueuePasswordReset(r.Context(), normalizedTo, req.Token); err != nil {
		s.logger.Error("enqueue password reset failed", "err", err)
		httpx.WriteError(w, nethttp.StatusBadGateway, "delivery_failed")
		return
	}
	httpx.WriteJSON(w, nethttp.StatusAccepted, map[string]string{"status": "queued"})
}

func (s *Server) handleSocial(w nethttp.ResponseWriter, r *nethttp.Request) {
	var req socialDeliveryRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, nethttp.StatusBadRequest, "bad_request")
		return
	}
	claims, ok := r.Context().Value(internalSocialClaimsKey{}).(internalSocialClaims)
	if !ok || strings.TrimSpace(claims.TenantID) == "" {
		httpx.WriteError(w, nethttp.StatusUnauthorized, "unauthorized")
		return
	}
	callerTenantID := strings.TrimSpace(claims.TenantID)
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.To = strings.TrimSpace(req.To)
	req.Kind = strings.TrimSpace(strings.ToLower(req.Kind))
	req.Subject = sanitizeNotificationText(req.Subject)
	req.Body = sanitizeNotificationText(req.Body)
	// The signed JWT claim is the canonical tenant authority. We reject any
	// mismatched body value to fail closed on stale or tampered payloads.
	if callerTenantID == "" || (req.TenantID != "" && !strings.EqualFold(req.TenantID, callerTenantID)) {
		httpx.WriteError(w, nethttp.StatusBadRequest, "bad_request")
		return
	}
	req.TenantID = callerTenantID
	if req.UserID <= 0 || req.TenantID == "" || req.Kind == "" || req.Subject == "" || req.Body == "" || req.To != "" {
		httpx.WriteError(w, nethttp.StatusBadRequest, "bad_request")
		return
	}
	if !isAllowedSocialKind(req.Kind) || !validHeaderValue(req.Subject) {
		httpx.WriteError(w, nethttp.StatusBadRequest, "bad_request")
		return
	}
	if s.authUsers == nil {
		httpx.WriteError(w, nethttp.StatusServiceUnavailable, "auth_unavailable")
		return
	}
	s.logger.Info("internal social notification request", "tenant_id", req.TenantID, "user_id", req.UserID, "kind", req.Kind)
	user, lookupErr := s.authUsers.LookupUser(r.Context(), req.UserID, req.TenantID)
	if lookupErr != nil {
		s.logger.Warn("notification user lookup failed", "user_id", req.UserID, "tenant_id", req.TenantID, "err", lookupErr)
		httpx.WriteError(w, nethttp.StatusBadGateway, "delivery_failed")
		return
	}
	if user == nil || user.ID != req.UserID || !strings.EqualFold(strings.TrimSpace(user.TenantID), req.TenantID) {
		httpx.WriteError(w, nethttp.StatusNotFound, "not_found")
		return
	}
	publicID, err := basestore.NewPublicID()
	if err != nil {
		s.logger.Error("generate notification id failed", "err", err)
		httpx.WriteError(w, nethttp.StatusBadGateway, "delivery_failed")
		return
	}
	notification, err := s.inbox.CreateNotification(r.Context(), basestore.Notification{
		PublicID:  publicID,
		TenantID:  req.TenantID,
		UserID:    req.UserID,
		Kind:      req.Kind,
		Subject:   req.Subject,
		Body:      req.Body,
		CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		s.logger.Error("store social notification failed", "err", err)
		httpx.WriteError(w, nethttp.StatusBadGateway, "delivery_failed")
		return
	}
	email := strings.TrimSpace(user.Email)
	if email != "" {
		if err := s.deliverer.EnqueueSocial(r.Context(), email, req.Subject, req.Body); err != nil {
			s.logger.Warn("enqueue social notification email failed", "user_id", req.UserID, "tenant_id", req.TenantID, "err", err)
		}
	}
	httpx.WriteJSON(w, nethttp.StatusAccepted, map[string]any{"status": "queued", "notification_id": notification.PublicID})
}

func normalizeEmailAddress(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || !validHeaderValue(value) {
		return "", errors.New("invalid email")
	}
	addr, err := mail.ParseAddress(value)
	if err != nil || strings.TrimSpace(addr.Address) == "" {
		return "", errors.New("invalid email")
	}
	return strings.TrimSpace(addr.Address), nil
}

func internalMailRateLimitKey(kind, email, callerToken string) string {
	hashInput := strings.TrimSpace(callerToken)
	if hashInput == "" {
		hashInput = "anonymous"
	}
	sum := sha256.Sum256([]byte(hashInput))
	return kind + "|email:" + strings.ToLower(strings.TrimSpace(email)) + "|caller:" + hex.EncodeToString(sum[:8])
}

func validHeaderValue(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && !strings.ContainsAny(value, "\r\n")
}

func sanitizeNotificationText(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	value = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || r == ' ' {
			return r
		}
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, value)
	return strings.TrimSpace(html.EscapeString(value))
}

func isAllowedSocialKind(value string) bool {
	switch value {
	case "follow", "friend_request", "friend_accept", "post_comment", "post_share", "event_invite", "playlist_share", "playlist_collaborator":
		return true
	default:
		return false
	}
}

func (s *Server) authenticated(next func(nethttp.ResponseWriter, *nethttp.Request, viewer)) nethttp.Handler {
	return nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if s.authn == nil {
			httpx.WriteError(w, nethttp.StatusServiceUnavailable, "auth_unavailable")
			return
		}
		v, err := s.authn.Required(r.Context(), r)
		if err != nil {
			if errors.Is(err, ErrUnauthorized) {
				httpx.WriteError(w, nethttp.StatusUnauthorized, "unauthorized")
				return
			}
			httpx.WriteError(w, nethttp.StatusBadGateway, "auth_unavailable")
			return
		}
		next(w, r, v)
	})
}

func (s *Server) handleListNotifications(w nethttp.ResponseWriter, r *nethttp.Request, viewer viewer) {
	limit := 20
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 || parsed > 100 {
			httpx.WriteError(w, nethttp.StatusBadRequest, "bad_request")
			return
		}
		limit = parsed
	}
	offset := 0
	if raw := strings.TrimSpace(r.URL.Query().Get("offset")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 {
			httpx.WriteError(w, nethttp.StatusBadRequest, "bad_request")
			return
		}
		offset = parsed
	}
	notifications, total, err := s.inbox.ListNotifications(r.Context(), viewer.TenantID, viewer.UserID, limit, offset)
	if err != nil {
		s.logger.Error("list notifications failed", "err", err)
		httpx.WriteError(w, nethttp.StatusBadGateway, "unavailable")
		return
	}
	unreadCount, err := s.inbox.CountUnread(r.Context(), viewer.TenantID, viewer.UserID)
	if err != nil {
		s.logger.Error("count unread notifications failed", "err", err)
		httpx.WriteError(w, nethttp.StatusBadGateway, "unavailable")
		return
	}
	hasMore := offset+len(notifications) < total
	var nextOffset *int
	if hasMore {
		value := offset + len(notifications)
		nextOffset = &value
	}
	httpx.WriteJSON(w, nethttp.StatusOK, notificationListResponse{
		Notifications: presentNotifications(notifications),
		Total:         total,
		UnreadCount:   unreadCount,
		Limit:         limit,
		Offset:        offset,
		HasMore:       hasMore,
		NextOffset:    nextOffset,
	})
}

func (s *Server) handleUnreadCount(w nethttp.ResponseWriter, r *nethttp.Request, viewer viewer) {
	count, err := s.inbox.CountUnread(r.Context(), viewer.TenantID, viewer.UserID)
	if err != nil {
		s.logger.Error("count unread notifications failed", "err", err)
		httpx.WriteError(w, nethttp.StatusBadGateway, "unavailable")
		return
	}
	httpx.WriteJSON(w, nethttp.StatusOK, map[string]int{"unread_count": count})
}

func (s *Server) handleReadNotification(w nethttp.ResponseWriter, r *nethttp.Request, viewer viewer) {
	notification, err := s.inbox.MarkNotificationRead(r.Context(), viewer.TenantID, viewer.UserID, strings.TrimSpace(r.PathValue("id")), time.Now().UTC())
	if err != nil {
		if errors.Is(err, basestore.ErrNotFound) {
			httpx.WriteError(w, nethttp.StatusNotFound, "not_found")
			return
		}
		s.logger.Error("mark notification read failed", "err", err)
		httpx.WriteError(w, nethttp.StatusBadGateway, "unavailable")
		return
	}
	unreadCount, err := s.inbox.CountUnread(r.Context(), viewer.TenantID, viewer.UserID)
	if err != nil {
		s.logger.Error("count unread notifications failed", "err", err)
		httpx.WriteError(w, nethttp.StatusBadGateway, "unavailable")
		return
	}
	httpx.WriteJSON(w, nethttp.StatusOK, map[string]any{
		"notification": presentNotification(notification),
		"unread_count": unreadCount,
	})
}

func (s *Server) handleReadAllNotifications(w nethttp.ResponseWriter, r *nethttp.Request, viewer viewer) {
	updated, err := s.inbox.MarkAllNotificationsRead(r.Context(), viewer.TenantID, viewer.UserID, time.Now().UTC())
	if err != nil {
		s.logger.Error("mark all notifications read failed", "err", err)
		httpx.WriteError(w, nethttp.StatusBadGateway, "unavailable")
		return
	}
	httpx.WriteJSON(w, nethttp.StatusOK, map[string]int{
		"marked_read":  updated,
		"unread_count": 0,
	})
}

func presentNotifications(in []basestore.Notification) []notificationResponse {
	out := make([]notificationResponse, 0, len(in))
	for _, notification := range in {
		out = append(out, presentNotification(notification))
	}
	return out
}

func presentNotification(notification basestore.Notification) notificationResponse {
	return notificationResponse{
		ID:        notification.PublicID,
		Kind:      notification.Kind,
		KindLabel: kindLabel(notification.Kind),
		KindGroup: kindGroup(notification.Kind),
		Subject:   notification.Subject,
		Body:      notification.Body,
		CreatedAt: notification.CreatedAt,
		ReadAt:    notification.ReadAt,
		IsRead:    notification.ReadAt != nil,
	}
}

func kindLabel(kind string) string {
	switch strings.TrimSpace(strings.ToLower(kind)) {
	case "follow":
		return "New follower"
	case "friend_request":
		return "Friend request"
	case "friend_accept":
		return "Friend request accepted"
	case "post_comment":
		return "New comment"
	case "post_share":
		return "Post shared"
	case "playlist_share":
		return "Playlist shared"
	case "playlist_collaborator":
		return "Playlist collaborator access"
	case "event_invite":
		return "Event invitation"
	default:
		return "Notification"
	}
}

func kindGroup(kind string) string {
	switch strings.TrimSpace(strings.ToLower(kind)) {
	case "follow", "friend_request", "friend_accept":
		return "social_graph"
	case "post_comment", "post_share", "playlist_share", "playlist_collaborator":
		return "content"
	case "event_invite":
		return "events"
	default:
		return "system"
	}
}
