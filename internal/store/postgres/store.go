package postgres

import (
	"context"
	"database/sql"
	"errors"
	"time"

	basestore "github.com/LCGant/role-notification/internal/store"
)

type Store struct {
	db *sql.DB
}

func New(db *sql.DB) *Store {
	return &Store{db: db}
}

func (s *Store) CreateNotification(ctx context.Context, notification basestore.Notification) (basestore.Notification, error) {
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO notifications (
			public_id,
			tenant_id,
			user_id,
			kind,
			subject,
			body,
			created_at,
			read_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		RETURNING id
	`,
		notification.PublicID,
		notification.TenantID,
		notification.UserID,
		notification.Kind,
		notification.Subject,
		notification.Body,
		notification.CreatedAt.UTC(),
		notification.ReadAt,
	).Scan(&notification.ID)
	return notification, err
}

func (s *Store) ListNotifications(ctx context.Context, tenantID string, userID int64, limit, offset int) ([]basestore.Notification, int, error) {
	if limit <= 0 {
		limit = 20
	}
	var total int
	if err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(1)
		FROM notifications
		WHERE tenant_id = $1 AND user_id = $2
	`, tenantID, userID).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, public_id, tenant_id, user_id, kind, subject, body, created_at, read_at
		FROM notifications
		WHERE tenant_id = $1 AND user_id = $2
		ORDER BY created_at DESC, id DESC
		LIMIT $3 OFFSET $4
	`, tenantID, userID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := make([]basestore.Notification, 0)
	for rows.Next() {
		var notification basestore.Notification
		if err := rows.Scan(
			&notification.ID,
			&notification.PublicID,
			&notification.TenantID,
			&notification.UserID,
			&notification.Kind,
			&notification.Subject,
			&notification.Body,
			&notification.CreatedAt,
			&notification.ReadAt,
		); err != nil {
			return nil, 0, err
		}
		out = append(out, notification)
	}
	return out, total, rows.Err()
}

func (s *Store) CountUnread(ctx context.Context, tenantID string, userID int64) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(1)
		FROM notifications
		WHERE tenant_id = $1 AND user_id = $2 AND read_at IS NULL
	`, tenantID, userID).Scan(&count)
	return count, err
}

func (s *Store) MarkNotificationRead(ctx context.Context, tenantID string, userID int64, publicID string, readAt time.Time) (basestore.Notification, error) {
	var notification basestore.Notification
	err := s.db.QueryRowContext(ctx, `
		UPDATE notifications
		SET read_at = COALESCE(read_at, $4)
		WHERE tenant_id = $1 AND user_id = $2 AND public_id = $3
		RETURNING id, public_id, tenant_id, user_id, kind, subject, body, created_at, read_at
	`, tenantID, userID, publicID, readAt.UTC()).Scan(
		&notification.ID,
		&notification.PublicID,
		&notification.TenantID,
		&notification.UserID,
		&notification.Kind,
		&notification.Subject,
		&notification.Body,
		&notification.CreatedAt,
		&notification.ReadAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return basestore.Notification{}, basestore.ErrNotFound
	}
	return notification, err
}

func (s *Store) MarkAllNotificationsRead(ctx context.Context, tenantID string, userID int64, readAt time.Time) (int, error) {
	result, err := s.db.ExecContext(ctx, `
		UPDATE notifications
		SET read_at = $3
		WHERE tenant_id = $1 AND user_id = $2 AND read_at IS NULL
	`, tenantID, userID, readAt.UTC())
	if err != nil {
		return 0, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	return int(affected), nil
}

var _ basestore.InboxStore = (*Store)(nil)
