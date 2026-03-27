package main

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/LCGant/role-notification/internal/config"
	"github.com/LCGant/role-notification/internal/delivery"
	httpserver "github.com/LCGant/role-notification/internal/http"
	"github.com/LCGant/role-notification/internal/sender"
	basestore "github.com/LCGant/role-notification/internal/store"
	"github.com/LCGant/role-notification/internal/store/memory"
	"github.com/LCGant/role-notification/internal/store/postgres"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError})).Error("config load failed", "err", err)
		os.Exit(1)
	}

	level := slog.LevelInfo
	switch cfg.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))

	backend := sender.New(cfg.Mail)
	queue := delivery.NewWithKeyring(cfg.QueueDir, cfg.QueueKeyVersion, cfg.QueueKeys, backend, logger)
	var inbox basestore.InboxStore
	var closeDB func()
	if cfg.DBURL != "" {
		db, err := sql.Open("pgx", cfg.DBURL)
		if err != nil {
			logger.Error("connect db failed", "err", err)
			os.Exit(1)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := db.PingContext(ctx); err != nil {
			logger.Error("db ping failed", "err", err)
			os.Exit(1)
		}
		inbox = postgres.New(db)
		closeDB = func() { _ = db.Close() }
	} else {
		inbox = memory.New()
	}
	if closeDB != nil {
		defer closeDB()
	}
	workerCtx, stopWorkers := context.WithCancel(context.Background())
	defer stopWorkers()
	server := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           httpserver.New(cfg, logger, queue, inbox),
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	go func() {
		logger.Info("listening", "addr", cfg.HTTPAddr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server error", "err", err)
			os.Exit(1)
		}
	}()
	go queue.Run(workerCtx)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	stopWorkers()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "err", err)
	}
}
