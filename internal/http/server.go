package http

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"expvar"
	"io"
	"log/slog"
	nethttp "net/http"
	"strconv"
	"strings"
	"time"

	"github.com/LCGant/role-notification/internal/authclient"
	"github.com/LCGant/role-notification/internal/config"
	"github.com/LCGant/role-notification/internal/delivery"
	basestore "github.com/LCGant/role-notification/internal/store"
	"github.com/LCGant/role-notification/internal/store/memory"
)

const maxBodyBytes = 1 << 20

type Server struct {
	cfg       config.Config
	logger    *slog.Logger
	deliverer *delivery.Service
	inbox     basestore.InboxStore
	authn     Authenticator
	authUsers *authclient.Client
	mux       *nethttp.ServeMux
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

func New(cfg config.Config, logger *slog.Logger, svc *delivery.Service, inbox basestore.InboxStore) nethttp.Handler {
	authn, err := newAuthenticator(cfg)
	if err != nil {
		panic(err)
	}
	return NewWithDependencies(cfg, logger, svc, inbox, authn, authclient.New(cfg.AuthBaseURL, cfg.AuthInternalToken))
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
	}
	s.routes()
	return s
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, nethttp.StatusOK, map[string]string{"status": "ok"})
	})
	s.mux.Handle("/metrics", s.metricsGuard(expvar.Handler()))
	s.mux.Handle("POST /internal/email-verification", s.internal(s.handleVerification))
	s.mux.Handle("POST /internal/password-reset", s.internal(s.handlePasswordReset))
	s.mux.Handle("POST /internal/social", s.internal(s.handleSocial))
	s.mux.Handle("GET /{$}", s.authenticated(s.handleListNotifications))
	s.mux.Handle("GET /unread-count", s.authenticated(s.handleUnreadCount))
	s.mux.Handle("POST /read-all", s.authenticated(s.handleReadAllNotifications))
	s.mux.Handle("POST /{id}/read", s.authenticated(s.handleReadNotification))
}

func (s *Server) ServeHTTP(w nethttp.ResponseWriter, r *nethttp.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) internal(next nethttp.HandlerFunc) nethttp.Handler {
	return nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(r.Header.Get("X-Internal-Token"))), []byte(s.cfg.InternalToken)) != 1 {
			writeError(w, nethttp.StatusUnauthorized, "unauthorized")
			return
		}
		next(w, r)
	})
}

func (s *Server) metricsGuard(next nethttp.Handler) nethttp.Handler {
	return nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if s.cfg.MetricsToken == "" {
			writeError(w, nethttp.StatusForbidden, "forbidden")
			return
		}
		if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(r.Header.Get("X-Metrics-Token"))), []byte(s.cfg.MetricsToken)) != 1 {
			writeError(w, nethttp.StatusForbidden, "forbidden")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleVerification(w nethttp.ResponseWriter, r *nethttp.Request) {
	var req deliveryRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, nethttp.StatusBadRequest, "bad_request")
		return
	}
	if req.To == "" || req.Token == "" {
		writeError(w, nethttp.StatusBadRequest, "bad_request")
		return
	}
	if err := s.deliverer.EnqueueVerification(r.Context(), strings.TrimSpace(req.To), strings.TrimSpace(req.Token)); err != nil {
		s.logger.Error("enqueue verification failed", "err", err)
		writeError(w, nethttp.StatusBadGateway, "delivery_failed")
		return
	}
	writeJSON(w, nethttp.StatusAccepted, map[string]string{"status": "queued"})
}

func (s *Server) handlePasswordReset(w nethttp.ResponseWriter, r *nethttp.Request) {
	var req deliveryRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, nethttp.StatusBadRequest, "bad_request")
		return
	}
	if req.To == "" || req.Token == "" {
		writeError(w, nethttp.StatusBadRequest, "bad_request")
		return
	}
	if err := s.deliverer.EnqueuePasswordReset(r.Context(), strings.TrimSpace(req.To), strings.TrimSpace(req.Token)); err != nil {
		s.logger.Error("enqueue password reset failed", "err", err)
		writeError(w, nethttp.StatusBadGateway, "delivery_failed")
		return
	}
	writeJSON(w, nethttp.StatusAccepted, map[string]string{"status": "queued"})
}

func (s *Server) handleSocial(w nethttp.ResponseWriter, r *nethttp.Request) {
	var req socialDeliveryRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, nethttp.StatusBadRequest, "bad_request")
		return
	}
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.To = strings.TrimSpace(req.To)
	req.Kind = strings.TrimSpace(strings.ToLower(req.Kind))
	req.Subject = strings.TrimSpace(req.Subject)
	req.Body = strings.TrimSpace(req.Body)
	if req.UserID <= 0 || req.TenantID == "" || req.Kind == "" || req.Subject == "" || req.Body == "" {
		writeError(w, nethttp.StatusBadRequest, "bad_request")
		return
	}
	publicID, err := basestore.NewPublicID()
	if err != nil {
		s.logger.Error("generate notification id failed", "err", err)
		writeError(w, nethttp.StatusBadGateway, "delivery_failed")
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
		writeError(w, nethttp.StatusBadGateway, "delivery_failed")
		return
	}
	email := req.To
	if email == "" && s.authUsers != nil {
		user, lookupErr := s.authUsers.LookupUser(r.Context(), req.UserID, req.TenantID)
		if lookupErr != nil {
			s.logger.Warn("notification user lookup failed", "user_id", req.UserID, "tenant_id", req.TenantID, "err", lookupErr)
		} else if user != nil {
			email = strings.TrimSpace(user.Email)
		}
	}
	if email != "" {
		if err := s.deliverer.EnqueueSocial(r.Context(), email, req.Subject, req.Body); err != nil {
			s.logger.Warn("enqueue social notification email failed", "user_id", req.UserID, "tenant_id", req.TenantID, "err", err)
		}
	}
	writeJSON(w, nethttp.StatusAccepted, map[string]any{"status": "queued", "notification_id": notification.PublicID})
}

func (s *Server) authenticated(next func(nethttp.ResponseWriter, *nethttp.Request, viewer)) nethttp.Handler {
	return nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if s.authn == nil {
			writeError(w, nethttp.StatusServiceUnavailable, "auth_unavailable")
			return
		}
		v, err := s.authn.Required(r.Context(), r)
		if err != nil {
			if errors.Is(err, ErrUnauthorized) {
				writeError(w, nethttp.StatusUnauthorized, "unauthorized")
				return
			}
			writeError(w, nethttp.StatusBadGateway, "auth_unavailable")
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
			writeError(w, nethttp.StatusBadRequest, "bad_request")
			return
		}
		limit = parsed
	}
	offset := 0
	if raw := strings.TrimSpace(r.URL.Query().Get("offset")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 {
			writeError(w, nethttp.StatusBadRequest, "bad_request")
			return
		}
		offset = parsed
	}
	notifications, total, err := s.inbox.ListNotifications(r.Context(), viewer.TenantID, viewer.UserID, limit, offset)
	if err != nil {
		s.logger.Error("list notifications failed", "err", err)
		writeError(w, nethttp.StatusBadGateway, "unavailable")
		return
	}
	unreadCount, err := s.inbox.CountUnread(r.Context(), viewer.TenantID, viewer.UserID)
	if err != nil {
		s.logger.Error("count unread notifications failed", "err", err)
		writeError(w, nethttp.StatusBadGateway, "unavailable")
		return
	}
	hasMore := offset+len(notifications) < total
	var nextOffset *int
	if hasMore {
		value := offset + len(notifications)
		nextOffset = &value
	}
	writeJSON(w, nethttp.StatusOK, notificationListResponse{
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
		writeError(w, nethttp.StatusBadGateway, "unavailable")
		return
	}
	writeJSON(w, nethttp.StatusOK, map[string]int{"unread_count": count})
}

func (s *Server) handleReadNotification(w nethttp.ResponseWriter, r *nethttp.Request, viewer viewer) {
	notification, err := s.inbox.MarkNotificationRead(r.Context(), viewer.TenantID, viewer.UserID, strings.TrimSpace(r.PathValue("id")), time.Now().UTC())
	if err != nil {
		if errors.Is(err, basestore.ErrNotFound) {
			writeError(w, nethttp.StatusNotFound, "not_found")
			return
		}
		s.logger.Error("mark notification read failed", "err", err)
		writeError(w, nethttp.StatusBadGateway, "unavailable")
		return
	}
	unreadCount, err := s.inbox.CountUnread(r.Context(), viewer.TenantID, viewer.UserID)
	if err != nil {
		s.logger.Error("count unread notifications failed", "err", err)
		writeError(w, nethttp.StatusBadGateway, "unavailable")
		return
	}
	writeJSON(w, nethttp.StatusOK, map[string]any{
		"notification": presentNotification(notification),
		"unread_count": unreadCount,
	})
}

func (s *Server) handleReadAllNotifications(w nethttp.ResponseWriter, r *nethttp.Request, viewer viewer) {
	updated, err := s.inbox.MarkAllNotificationsRead(r.Context(), viewer.TenantID, viewer.UserID, time.Now().UTC())
	if err != nil {
		s.logger.Error("mark all notifications read failed", "err", err)
		writeError(w, nethttp.StatusBadGateway, "unavailable")
		return
	}
	writeJSON(w, nethttp.StatusOK, map[string]int{
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
	case "post_comment", "playlist_share", "playlist_collaborator":
		return "content"
	case "event_invite":
		return "events"
	default:
		return "system"
	}
}

func decodeJSON(r *nethttp.Request, dst any) error {
	payload, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		return err
	}
	if int64(len(payload)) > maxBodyBytes {
		return errors.New("too_large")
	}
	dec := json.NewDecoder(strings.NewReader(string(payload)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if err := dec.Decode(new(struct{})); err != io.EOF {
		return errors.New("trailing_data")
	}
	return nil
}

func writeJSON(w nethttp.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w nethttp.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}
