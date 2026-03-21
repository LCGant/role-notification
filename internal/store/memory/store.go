package memory

import (
	"context"
	"sort"
	"sync"
	"time"

	basestore "github.com/LCGant/role-notification/internal/store"
)

type Store struct {
	mu            sync.RWMutex
	nextID        int64
	notifications []basestore.Notification
}

func New() *Store {
	return &Store{nextID: 1}
}

func (s *Store) CreateNotification(_ context.Context, notification basestore.Notification) (basestore.Notification, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	notification.ID = s.nextID
	s.nextID++
	s.notifications = append(s.notifications, notification)
	return notification, nil
}

func (s *Store) ListNotifications(_ context.Context, tenantID string, userID int64, limit, offset int) ([]basestore.Notification, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	filtered := make([]basestore.Notification, 0)
	for _, notification := range s.notifications {
		if notification.TenantID == tenantID && notification.UserID == userID {
			filtered = append(filtered, notification)
		}
	}
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].CreatedAt.After(filtered[j].CreatedAt)
	})
	total := len(filtered)
	if offset > total {
		return []basestore.Notification{}, total, nil
	}
	end := offset + limit
	if end > total {
		end = total
	}
	if limit <= 0 {
		end = total
	}
	return append([]basestore.Notification(nil), filtered[offset:end]...), total, nil
}

func (s *Store) CountUnread(_ context.Context, tenantID string, userID int64) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	count := 0
	for _, notification := range s.notifications {
		if notification.TenantID == tenantID && notification.UserID == userID && notification.ReadAt == nil {
			count++
		}
	}
	return count, nil
}

func (s *Store) MarkNotificationRead(_ context.Context, tenantID string, userID int64, publicID string, readAt time.Time) (basestore.Notification, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.notifications {
		notification := &s.notifications[i]
		if notification.TenantID == tenantID && notification.UserID == userID && notification.PublicID == publicID {
			if notification.ReadAt == nil {
				copyTime := readAt.UTC()
				notification.ReadAt = &copyTime
			}
			return *notification, nil
		}
	}
	return basestore.Notification{}, basestore.ErrNotFound
}

func (s *Store) MarkAllNotificationsRead(_ context.Context, tenantID string, userID int64, readAt time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	updated := 0
	for i := range s.notifications {
		notification := &s.notifications[i]
		if notification.TenantID == tenantID && notification.UserID == userID && notification.ReadAt == nil {
			copyTime := readAt.UTC()
			notification.ReadAt = &copyTime
			updated++
		}
	}
	return updated, nil
}

var _ basestore.InboxStore = (*Store)(nil)
