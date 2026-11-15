# Jargonet web chat

A working username/password chat application. The page is static; accounts,
presence, friend requests and messages are handled by one same-origin Function
and a private database.

## Local development

```bash
# certificate for https://localhost:8443
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -keyout dev/key.pem -out dev/cert.pem -subj "/CN=localhost"

node dev/server.mjs --cert dev/cert.pem --key dev/key.pem
```

Use the portable Node runtime if `node` is not on PATH. The local server uses
an in-memory database and never talks to the deployed database. Open
`https://localhost:8443` and accept the self-signed certificate.

Run the backend contract checks with:

```bash
node --test dev/chat.test.mjs
```

## Self-hosted build

`server.mjs` runs the same client and the same `functions/` router on a plain
Node process with a SQLite file, so the app no longer depends on a managed
runtime. It needs Node 22.5 or newer for `node:sqlite`; there are no npm
dependencies to install.

```bash
node server.mjs                 # http://localhost:3000
PORT=8080 node server.mjs       # pick a port
DATA_DIR=/var/lib/jargonet node server.mjs   # pick where the database lives
```

The database is created at `data/jargonet.db` on first start from
`schema.sqlite.sql`, which mirrors `schema.sql` column for column. Every
statement is `IF NOT EXISTS`, so restarting never touches existing rows.
`node dev/e2e-sqlite.mjs` exercises the whole API against a running server:
registration, login, friends, messages, rooms, relay and session revocation.

Two differences from the managed deployment:

- The client calls `/functions/v1/app/api/*`, so the server serves the API on
  that path and also on `/api/*`. The browser client is unchanged.
- `requireTrustedOrigin` compares the browser `Origin` against the request's own
  `Host` instead of a hardcoded domain, so one build works on any domain. It
  still rejects cross-origin writes.

## Deployment

The public output is `web/`; the Function entry is `functions/index.ts`; the
reviewed schema is `schema.sql`. The deployed site must set `PUBLIC_ORIGIN` in
`functions/http.mjs` to its exact HTTPS origin (the CSRF check rejects writes
from any other origin). The database is function-backed and assigned to the
site project during preparation.

## Data model & Cryptography

- `users` stores the username, PBKDF2 verifier, identity keys and last heartbeat.
- `sessions` stores only SHA-256 digests of opaque session tokens.
- `friend_requests` is unique per direction; accept creates two directed
  `friendships` rows and provisions a dedicated `rooms` entry.
- `rooms` stores distinct keypairs per chatroom (`public_key`, `private_key`,
  `key_algorithm`), allowing bearer-based group participation via "Join a chat".
- `room_members` tracks participants who hold or joined via the room private key.
- `relay_packets` holds transient opaque onion envelopes for the peer hopping network;
  retrieved packets are immediately flushed to prevent tracking trails.
- `messages` stores end-to-end encrypted ciphertexts (`body`, `nonce`, `hop_count`,
  `hop_trail`). The server never stores or sees plaintext messages.

## Privacy & Peer Hopping Architecture

- **Room Keypairs**: Each chatroom has a distinct Public and Private Key. Anyone with
  the chatroom's Private Key can tap into the conversation via **Join a chat**, enabling
  spontaneous group conversations without centralized administration.
- **End-to-End Encryption**: Messages are encrypted client-side using AES-256-GCM with
  per-message 96-bit random IVs and PBKDF2-SHA256 (100,000 iterations).
- **Peer Hopping (Shifting Relays)**: Outgoing messages are onion-routed through
  active online users acting as intermediate relays. Intermediate nodes forward opaque
  payloads without decryption ability, and retain zero records of past transmissions.

The browser polls presence every 4 seconds and the open conversation every
2 seconds. A user is shown online while their last heartbeat is under
35 seconds old. No cookies beyond the HttpOnly session, no analytics.
