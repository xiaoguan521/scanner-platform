-- PostgreSQL notification center and safe webhook outbox.
BEGIN;
SET LOCAL search_path TO public;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version = '0012_schedules') THEN
        RAISE EXCEPTION 'Apply 0012_schedules.sql before 0013_notifications.sql';
    END IF;
END
$$;

CREATE TABLE notifications (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    object_type TEXT NOT NULL,
    object_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    read_at TIMESTAMPTZ
);
CREATE INDEX idx_notifications_read_created
    ON notifications(read_at, created_at DESC, id DESC);

CREATE TABLE notification_deliveries (
    id TEXT PRIMARY KEY,
    notification_id TEXT NOT NULL UNIQUE REFERENCES notifications(id) ON DELETE CASCADE,
    state TEXT NOT NULL CHECK (state IN ('PENDING', 'SENDING', 'FAILED', 'DELIVERED', 'DEAD')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at TIMESTAMPTZ NOT NULL,
    last_error TEXT NOT NULL DEFAULT '',
    delivered_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_notification_deliveries_queue
    ON notification_deliveries(state, next_attempt_at, created_at, id);

INSERT INTO schema_migrations(version) VALUES ('0013_notifications');
COMMIT;
