package http

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"expvar"
	"io"
	"log/slog"
	nethttp "net/http"
	"strings"

	"github.com/LCGant/role-notification/internal/config"
	"github.com/LCGant/role-notification/internal/delivery"
)

const maxBodyBytes = 1 << 20

type Server struct {
	cfg       config.Config
	logger    *slog.Logger
	deliverer *delivery.Service
	mux       *nethttp.ServeMux
}

type deliveryRequest struct {
	To    string `json:"to"`
	Token string `json:"token"`
}

func New(cfg config.Config, logger *slog.Logger, svc *delivery.Service) nethttp.Handler {
	s := &Server{
		cfg:       cfg,
		logger:    logger,
		deliverer: svc,
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
