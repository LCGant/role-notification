package http

import (
	nethttp "net/http"
	"strconv"
	"strings"
	"time"

	basestore "github.com/LCGant/role-notification/internal/store"
)

type notificationListQuery struct {
	Limit  int
	Offset int
	Cursor string
}

func parseNotificationListQuery(r *nethttp.Request) (notificationListQuery, error) {
	query := notificationListQuery{Limit: 20}
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 || parsed > 100 {
			return notificationListQuery{}, errBadRequest
		}
		query.Limit = parsed
	}
	cursor := strings.TrimSpace(r.URL.Query().Get("cursor"))
	if cursor != "" {
		parsed, err := strconv.Atoi(cursor)
		if err != nil || parsed < 0 {
			return notificationListQuery{}, errBadRequest
		}
		query.Offset = parsed
		query.Cursor = cursor
		return query, nil
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("offset")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 {
			return notificationListQuery{}, errBadRequest
		}
		query.Offset = parsed
		query.Cursor = cursorValue(parsed)
	}
	return query, nil
}

func newNotificationListResponse(items []basestore.Notification, total, unreadCount int, query notificationListQuery) notificationListResponse {
	hasMore := query.Offset+len(items) < total
	var nextOffset *int
	nextCursor := ""
	if hasMore {
		value := query.Offset + len(items)
		nextOffset = &value
		nextCursor = strconv.Itoa(value)
	}
	return notificationListResponse{
		Notifications: presentNotifications(items),
		Total:         total,
		UnreadCount:   unreadCount,
		Limit:         query.Limit,
		Offset:        query.Offset,
		Cursor:        query.Cursor,
		HasMore:       hasMore,
		NextOffset:    nextOffset,
		NextCursor:    nextCursor,
	}
}

func newUnreadCountResponse(count int) map[string]int {
	return map[string]int{"unread_count": count}
}

func newReadNotificationResponse(notification basestore.Notification, unreadCount int) map[string]any {
	return map[string]any{
		"notification": presentNotification(notification),
		"unread_count": unreadCount,
	}
}

func newReadAllResponse(markedRead int) map[string]int {
	return map[string]int{
		"marked_read":  markedRead,
		"unread_count": 0,
	}
}

var errBadRequest = badRequestError("bad_request")

type badRequestError string

func (e badRequestError) Error() string { return string(e) }

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

func cursorValue(offset int) string {
	if offset <= 0 {
		return ""
	}
	return strconv.Itoa(offset)
}

func normalizeNotificationKind(kind string) string {
	return strings.TrimSpace(strings.ToLower(kind))
}

func notificationCreatedAt(now time.Time) time.Time {
	return now.UTC()
}
