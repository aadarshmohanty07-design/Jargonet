-- SQLite schema for the self-hosted build.
-- Mirrors schema.sql column for column. UUIDs and timestamps are stored as
-- TEXT: timestamps are ISO-8601 UTC strings, which sort correctly in ORDER BY
-- and parse with Date.parse. Applied on every start; every statement is
-- idempotent so an existing database keeps its rows.

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  password_salt TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  password_iterations INTEGER NOT NULL,
  public_key TEXT NOT NULL,
  private_key TEXT NOT NULL,
  key_algorithm TEXT NOT NULL,
  created_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  token_digest TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS auth_limiter (
  key TEXT PRIMARY KEY,
  window_started_at TEXT NOT NULL,
  attempt_count INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS friend_requests (
  id TEXT PRIMARY KEY,
  from_user_id TEXT NOT NULL,
  to_user_id TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  responded_at TEXT,
  UNIQUE (from_user_id, to_user_id)
);

CREATE TABLE IF NOT EXISTS friendships (
  user_id TEXT NOT NULL,
  friend_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (user_id, friend_id)
);

CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY,
  conversation_key TEXT NOT NULL,
  room_id TEXT,
  sender_id TEXT NOT NULL,
  recipient_id TEXT,
  body TEXT NOT NULL,
  nonce TEXT NOT NULL DEFAULT '',
  hop_count INTEGER NOT NULL DEFAULT 1,
  hop_trail TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rooms (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  public_key TEXT NOT NULL,
  private_key TEXT NOT NULL,
  key_algorithm TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS room_members (
  room_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  joined_at TEXT NOT NULL,
  PRIMARY KEY (room_id, user_id)
);

CREATE TABLE IF NOT EXISTS relay_packets (
  id TEXT PRIMARY KEY,
  recipient_id TEXT NOT NULL,
  payload TEXT NOT NULL,
  hop_count INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS users_last_seen_idx ON users (last_seen_at);
CREATE INDEX IF NOT EXISTS friend_requests_to_status_idx ON friend_requests (to_user_id, status);
CREATE INDEX IF NOT EXISTS friend_requests_from_status_idx ON friend_requests (from_user_id, status);
CREATE INDEX IF NOT EXISTS messages_conversation_created_idx ON messages (conversation_key, created_at);
CREATE INDEX IF NOT EXISTS messages_room_created_idx ON messages (room_id, created_at);
CREATE INDEX IF NOT EXISTS room_members_user_idx ON room_members (user_id);
CREATE INDEX IF NOT EXISTS relay_packets_recipient_idx ON relay_packets (recipient_id);
