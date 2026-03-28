package http

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"expvar"
	"html"
	"log/slog"
	nethttp "net/http"
	"net/mail"
	"strings"
	"time"
	"unicode"

	libcrypto "github.com/LCGant/role-crypto"
	"github.com/LCGant/role-httpx"
	internaltoken "github.com/LCGant/role-internaltoken"
	"github.com/LCGant/role-notification/internal/auditclient"
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
	audit       *auditclient.Client
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
	Cursor        string                 `json:"cursor,omitempty"`
	HasMore       bool                   `json:"has_more"`
	NextOffset    *int                   `json:"next_offset,omitempty"`
	NextCursor    string                 `json:"next_cursor,omitempty"`
}

type internalSocialClaims struct {
	Subject  string
	Scope    string
	TenantID string
}

type internalSocialClaimsKey struct{}

type socialKindMeta struct {
	Label string
	Group string
}

var socialKinds = map[string]socialKindMeta{
	"follow":                {Label: "New follower", Group: "social_graph"},
	"friend_request":        {Label: "Friend request", Group: "social_graph"},
	"friend_accept":         {Label: "Friend request accepted", Group: "social_graph"},
	"post_comment":          {Label: "New comment", Group: "content"},
	"post_share":            {Label: "Post shared", Group: "content"},
	"playlist_share":        {Label: "Playlist shared", Group: "content"},
	"playlist_collaborator": {Label: "Playlist collaborator access", Group: "content"},
	"event_invite":          {Label: "Event invitation", Group: "events"},
}

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
		audit:     auditclient.New(cfg),
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
	} else if logger != nil {
		logger.Warn("notification service bearer verifier disabled: no public keys configured")
	}
	s.routes()
	return s
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Header().Set("Cache-Control", "no-store")
		httpx.WriteJSON(w, nethttp.StatusOK, map[string]string{"status": "ok"})
	})
	s.mux.HandleFunc("GET /readyz", func(w nethttp.ResponseWriter, r *nethttp.Request) {
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
	var handler nethttp.Handler = s.mux
	handler = s.loggingMiddleware(handler)
	handler = s.recoveryMiddleware(handler)
	handler = notificationRequestIDMiddleware(handler)
	handler.ServeHTTP(w, r)
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
	s.handleEmailDelivery(w, r, "verify", "notification:verify:sent", s.deliverer.EnqueueVerification)
}

func (s *Server) handlePasswordReset(w nethttp.ResponseWriter, r *nethttp.Request) {
	s.handleEmailDelivery(w, r, "reset", "notification:reset:sent", s.deliverer.EnqueuePasswordReset)
}

func (s *Server) handleEmailDelivery(w nethttp.ResponseWriter, r *nethttp.Request, rateLimitKind, auditEventType string, enqueue func(context.Context, string, string) error) {
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
	if s.mailLimiter != nil && !s.mailLimiter.Allow(internalMailRateLimitKey(rateLimitKind, normalizedTo, strings.TrimSpace(r.Header.Get("X-Internal-Token")))) {
		httpx.WriteError(w, nethttp.StatusTooManyRequests, "rate_limit_exceeded")
		return
	}
	if err := enqueue(r.Context(), normalizedTo, req.Token); err != nil {
		s.logger.Error("enqueue internal email delivery failed", "kind", rateLimitKind, "err", err)
		httpx.WriteError(w, nethttp.StatusBadGateway, "delivery_failed")
		return
	}
	s.recordAudit(r.Context(), auditclient.Event{
		Source:    "notification",
		EventType: auditEventType,
		Success:   true,
		Metadata:  map[string]any{"email_hash": hashEmail(normalizedTo), "delivery": "queued"},
		CreatedAt: time.Now().UTC(),
	})
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
	emailDelivery := "skipped"
	if email != "" {
		emailDelivery = "queued"
		if err := s.deliverer.EnqueueSocial(r.Context(), email, req.Subject, req.Body); err != nil {
			s.logger.Warn("enqueue social notification email failed", "user_id", req.UserID, "tenant_id", req.TenantID, "err", err)
			emailDelivery = "failed"
		}
	}
	httpx.WriteJSON(w, nethttp.StatusAccepted, map[string]any{
		"status":          "queued",
		"notification_id": notification.PublicID,
		"email_delivery":  emailDelivery,
	})
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
	_, ok := socialKinds[normalizeNotificationKind(value)]
	return ok
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
	query, err := parseNotificationListQuery(r)
	if err != nil {
		httpx.WriteError(w, nethttp.StatusBadRequest, "bad_request")
		return
	}
	notifications, total, err := s.inbox.ListNotifications(r.Context(), viewer.TenantID, viewer.UserID, query.Limit, query.Offset)
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
	httpx.WriteJSON(w, nethttp.StatusOK, newNotificationListResponse(notifications, total, unreadCount, query))
}

type notificationContextKey string

const notificationRequestIDKey notificationContextKey = "requestID"

func notificationRequestIDFromContext(ctx context.Context) string {
	value, _ := ctx.Value(notificationRequestIDKey).(string)
	return value
}

func notificationRequestIDMiddleware(next nethttp.Handler) nethttp.Handler {
	return nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		requestID := strings.TrimSpace(r.Header.Get("X-Request-Id"))
		if requestID == "" {
			buf := make([]byte, 8)
			if _, err := rand.Read(buf); err == nil {
				requestID = hex.EncodeToString(buf)
			}
		}
		if requestID == "" {
			requestID = "unknown"
		}
		r.Header.Set("X-Request-Id", requestID)
		w.Header().Set("X-Request-Id", requestID)
		ctx := context.WithValue(r.Context(), notificationRequestIDKey, requestID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) loggingMiddleware(next nethttp.Handler) nethttp.Handler {
	logger := s.logger
	if logger == nil {
		logger = slog.Default()
	}
	return nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		logger.InfoContext(r.Context(), "http_request",
			"method", r.Method,
			"path", r.URL.Path,
			"request_id", notificationRequestIDFromContext(r.Context()),
			"duration_ms", time.Since(start).Milliseconds(),
		)
	})
}

func (s *Server) recoveryMiddleware(next nethttp.Handler) nethttp.Handler {
	logger := s.logger
	if logger == nil {
		logger = slog.Default()
	}
	return nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				logger.Error("panic_recovered", "error", "internal_error", "request_id", notificationRequestIDFromContext(r.Context()))
				httpx.WriteError(w, nethttp.StatusInternalServerError, "internal_error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleUnreadCount(w nethttp.ResponseWriter, r *nethttp.Request, viewer viewer) {
	count, err := s.inbox.CountUnread(r.Context(), viewer.TenantID, viewer.UserID)
	if err != nil {
		s.logger.Error("count unread notifications failed", "err", err)
		httpx.WriteError(w, nethttp.StatusBadGateway, "unavailable")
		return
	}
	httpx.WriteJSON(w, nethttp.StatusOK, newUnreadCountResponse(count))
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
	httpx.WriteJSON(w, nethttp.StatusOK, newReadNotificationResponse(notification, unreadCount))
	s.recordAudit(r.Context(), auditclient.Event{
		Source:    "notification",
		EventType: "notification:read",
		UserID:    &viewer.UserID,
		TenantID:  viewer.TenantID,
		Success:   true,
		Metadata:  map[string]any{"notification_id": notification.PublicID},
		CreatedAt: notificationCreatedAt(time.Now()),
	})
}

func (s *Server) handleReadAllNotifications(w nethttp.ResponseWriter, r *nethttp.Request, viewer viewer) {
	updated, err := s.inbox.MarkAllNotificationsRead(r.Context(), viewer.TenantID, viewer.UserID, time.Now().UTC())
	if err != nil {
		s.logger.Error("mark all notifications read failed", "err", err)
		httpx.WriteError(w, nethttp.StatusBadGateway, "unavailable")
		return
	}
	httpx.WriteJSON(w, nethttp.StatusOK, newReadAllResponse(updated))
	s.recordAudit(r.Context(), auditclient.Event{
		Source:    "notification",
		EventType: "notification:read-all",
		UserID:    &viewer.UserID,
		TenantID:  viewer.TenantID,
		Success:   true,
		Metadata:  map[string]any{"marked_read": updated},
		CreatedAt: notificationCreatedAt(time.Now()),
	})
}

func kindLabel(kind string) string {
	if meta, ok := socialKinds[normalizeNotificationKind(kind)]; ok {
		return meta.Label
	}
	return "Notification"
}

func kindGroup(kind string) string {
	if meta, ok := socialKinds[normalizeNotificationKind(kind)]; ok {
		return meta.Group
	}
	return "system"
}

func (s *Server) recordAudit(ctx context.Context, event auditclient.Event) {
	if s.audit == nil {
		return
	}
	if err := s.audit.Record(ctx, event); err != nil && s.logger != nil {
		s.logger.Warn("notification audit forward dropped", "event", event.EventType, "err", err)
	}
}

func hashEmail(value string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(value))))
	return hex.EncodeToString(sum[:8])
}
