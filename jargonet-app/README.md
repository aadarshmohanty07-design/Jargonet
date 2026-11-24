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

Two ways to run it, both on a single port.

**Local storage.** `node server.mjs` serves `web/` and the JSON API, keeping rows
in a SQLite file under `data/`. No dependencies, no external database.

**Forwarding to an existing backend.** If `JARGONET_UPSTREAM` (or the file
`proxy-upstream.txt`) holds a base URL, API calls are forwarded there instead
and the SQLite file is not opened. Static files still come from this repository.

The second mode exists for one situation: moving the page to another domain
without orphaning the accounts and messages already stored in a live
deployment. Because the session cookie is `__Host-app_auth.session` — a prefix
that forbids a `Domain` attribute — a forwarded `Set-Cookie` binds to whatever
host set it, so people stay signed in through the new origin. The server also
rewrites `Origin` to the upstream host, since that backend rejects writes from
any other origin.

Note what this mode does and does not do. It changes where the page is served
from; it does not copy the data. The rows stay in the original database, so
that backend must remain reachable. Use it as a bridge, not as a migration.

The public output is `web/`; the Function entry is `functions/index.ts`; the
reviewed schema is `schema.sql`. `requireTrustedOrigin` accepts an explicit
origin when one is passed and otherwise compares the browser `Origin` against
the request's own `Host`, so one build works on any domain.

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
