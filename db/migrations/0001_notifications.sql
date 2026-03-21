CREATE TABLE IF NOT EXISTS notifications (
    id BIGSERIAL PRIMARY KEY,
    public_id TEXT NOT NULL UNIQUE,
    tenant_id TEXT NOT NULL,
    user_id BIGINT NOT NULL,
    kind TEXT NOT NULL,
    subject TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    read_at TIMESTAMPTZ NULL
);

CREATE INDEX IF NOT EXISTS idx_notifications_tenant_user_created
    ON notifications (tenant_id, user_id, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_notifications_tenant_user_unread
    ON notifications (tenant_id, user_id)
    WHERE read_at IS NULL;
