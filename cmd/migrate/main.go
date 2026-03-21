package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	dbURL := strings.TrimSpace(os.Getenv("NOTIFICATION_DB_URL"))
	if dbURL == "" {
		dbURL = strings.TrimSpace(os.Getenv("DATABASE_URL"))
	}
	if dbURL == "" {
		logger.Error("NOTIFICATION_DB_URL (or DATABASE_URL) must be set for migrations")
		os.Exit(1)
	}

	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		logger.Error("failed to open database", "error", err)
		os.Exit(1)
	}
	db.SetMaxOpenConns(1)
	db.SetConnMaxLifetime(5 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		logger.Error("database ping failed", "error", err)
		os.Exit(1)
	}

	if err := runMigrations(ctx, db, "db/migrations", logger); err != nil {
		logger.Error("migrations failed", "error", err)
		os.Exit(1)
	}

	logger.Info("migrations applied successfully")
}

func runMigrations(ctx context.Context, db *sql.DB, dir string, logger *slog.Logger) error {
	if dir == "" {
		return errors.New("migration directory not provided")
	}

	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	files, err := filepath.Glob(filepath.Join(dir, "*.sql"))
	if err != nil {
		return fmt.Errorf("list migrations: %w", err)
	}
	if len(files) == 0 {
		return fmt.Errorf("no migrations found in %s", dir)
	}
	sort.Strings(files)

	for _, path := range files {
		version := filepath.Base(path)
		applied, err := migrationApplied(ctx, db, version)
		if err != nil {
			return err
		}
		if applied {
			logger.Info("migration already applied", "version", version)
			continue
		}

		body, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", version, err)
		}

		logger.Info("applying migration", "version", version)
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin tx: %w", err)
		}
		if _, err := tx.ExecContext(ctx, string(body)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("apply migration %s: %w", version, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, version); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("record migration %s: %w", version, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %s: %w", version, err)
		}
	}
	return nil
}

func migrationApplied(ctx context.Context, db *sql.DB, version string) (bool, error) {
	var count int
	err := db.QueryRowContext(ctx, `SELECT COUNT(1) FROM schema_migrations WHERE version = $1`, version).Scan(&count)
	return count > 0, err
}
