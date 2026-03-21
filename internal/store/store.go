package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"
)

var ErrNotFound = errors.New("not found")

type Notification struct {
	ID        int64      `json:"-"`
	PublicID  string     `json:"id"`
	TenantID  string     `json:"-"`
	UserID    int64      `json:"-"`
	Kind      string     `json:"kind"`
	Subject   string     `json:"subject"`
	Body      string     `json:"body"`
	CreatedAt time.Time  `json:"created_at"`
	ReadAt    *time.Time `json:"read_at,omitempty"`
}

type InboxStore interface {
	CreateNotification(context.Context, Notification) (Notification, error)
	ListNotifications(context.Context, string, int64, int, int) ([]Notification, int, error)
	CountUnread(context.Context, string, int64) (int, error)
	MarkNotificationRead(context.Context, string, int64, string, time.Time) (Notification, error)
	MarkAllNotificationsRead(context.Context, string, int64, time.Time) (int, error)
}

func NewPublicID() (string, error) {
	var raw [12]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return "ntf_" + hex.EncodeToString(raw[:]), nil
}
