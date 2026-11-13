-- Jargonet web chat: application-owned accounts, presence, friendships and messages.
-- All browser access goes through the site Function; no direct database grants.

CREATE TABLE app.users (
  id uuid PRIMARY KEY,
  username text NOT NULL UNIQUE,
  password_salt text NOT NULL,
  password_hash text NOT NULL,
  password_iterations integer NOT NULL,
  public_key text NOT NULL,
  private_key text NOT NULL,
  key_algorithm text NOT NULL,
  created_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL
);

CREATE TABLE app.sessions (
  token_digest text PRIMARY KEY,
  user_id uuid NOT NULL,
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz
);

CREATE TABLE app.auth_limiter (
  key text PRIMARY KEY,
  window_started_at timestamptz NOT NULL,
  attempt_count integer NOT NULL
);

CREATE TABLE app.friend_requests (
  id uuid PRIMARY KEY,
  from_user_id uuid NOT NULL,
  to_user_id uuid NOT NULL,
  status text NOT NULL,
  created_at timestamptz NOT NULL,
  responded_at timestamptz,
  UNIQUE (from_user_id, to_user_id)
);

CREATE TABLE app.friendships (
  user_id uuid NOT NULL,
  friend_id uuid NOT NULL,
  created_at timestamptz NOT NULL,
  PRIMARY KEY (user_id, friend_id)
);

CREATE TABLE app.messages (
  id uuid PRIMARY KEY,
  conversation_key text NOT NULL,
  room_id uuid,
  sender_id uuid NOT NULL,
  recipient_id uuid,
  body text NOT NULL,
  nonce text NOT NULL DEFAULT '',
  hop_count integer NOT NULL DEFAULT 1,
  hop_trail text,
  created_at timestamptz NOT NULL
);

CREATE TABLE app.rooms (
  id uuid PRIMARY KEY,
  name text NOT NULL,
  public_key text NOT NULL,
  private_key text NOT NULL,
  key_algorithm text NOT NULL,
  created_by uuid NOT NULL,
  created_at timestamptz NOT NULL
);

CREATE TABLE app.room_members (
  room_id uuid NOT NULL,
  user_id uuid NOT NULL,
  joined_at timestamptz NOT NULL,
  PRIMARY KEY (room_id, user_id)
);

CREATE TABLE app.relay_packets (
  id uuid PRIMARY KEY,
  recipient_id uuid NOT NULL,
  payload text NOT NULL,
  hop_count integer NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL
);

CREATE INDEX users_last_seen_idx ON app.users (last_seen_at);
CREATE INDEX friend_requests_to_status_idx ON app.friend_requests (to_user_id, status);
CREATE INDEX friend_requests_from_status_idx ON app.friend_requests (from_user_id, status);
CREATE INDEX messages_conversation_created_idx ON app.messages (conversation_key, created_at);
CREATE INDEX messages_room_created_idx ON app.messages (room_id, created_at);
CREATE INDEX room_members_user_idx ON app.room_members (user_id);
CREATE INDEX relay_packets_recipient_idx ON app.relay_packets (recipient_id);
