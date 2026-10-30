# Jargonet protocol

This document describes the on-the-wire and at-rest formats implemented by this
repository. It is a design description, not a promise of wire stability; the
protocol version is 1.

All integers on the wire are big endian unless stated otherwise. Public keys
are X25519 (`32` bytes); identity signing keys are Ed25519 (`32` public, `64`
secret); nonces are `24` bytes; session ids are `16` bytes.

## 1. Identities and local files

An identity contains:

- a display username (1-32 printable bytes, not globally unique),
- an X25519 box key pair (`crypto_box_keypair`),
- an Ed25519 signing key pair.

The fingerprint shown in the UI is the uppercase hex of the first 16 bytes of
`BLAKE2b-256(public_key)`. The full public key remains the actual identity; the
fingerprint is a display and lookup aid.

`identity.jnid`:

```
"JNID1" | salt[16] | ops_limit(u64) | mem_limit(u64) |
secretbox(nonce[24] | ciphertext)
```

The secretbox key is Argon2id(password, salt, ops_limit, mem_limit). The
plaintext is a MessagePack map containing `v`, `u` (username), `pk`, `sk`,
`spk`, `ssk` and an algorithm label. The private keys never leave this file in
plaintext. A wrong password fails secretbox authentication.

`store.jnst` uses the same envelope with magic `JNST1`. Its secretbox plaintext
is a MessagePack map with contacts, session metadata and messages. Contacts
contain only public key, signing key and display name. Session metadata contains
the session id, peer public keys/names, group flag, initiator flag and group
member list. Messages contain session id, sender public key/name, direction,
text and a sequence number. **Timestamps, IP addresses, relay paths and session
keys are not stored.**

## 2. UDP packets

```
offset  size  field
0       4     magic "JGN1"
4       1     protocol version (1)
5       1     packet type
6       1     flags (bit 0 = delivered through an onion)
7       1     ttl (0..8)
8       16    session id (zero for control packets)
24      8     message id
32      24    nonce (header-level, used by sender boxes)
56      2     payload length
58      ...   payload
```

A datagram is at most 1200 bytes, so the payload is at most 1142 bytes. This
avoids IP fragmentation on typical paths. Unknown versions, types, lengths,
TTLs and trailing bytes are rejected.

Packet types:

| Value | Name | Purpose |
| --- | --- | --- |
| 1 | DISCOVERY | reserved |
| 2 | CHAT_REQUEST | sender-boxed chat invitation |
| 3 | CHAT_ACCEPT | sender-boxed session confirmation |
| 4 | ONION_DATA | sealed onion layer |
| 5 | ACK | acknowledges a message id |
| 6 | RELAY_ANNOUNCE | reserved |
| 7 | DIRECT | encrypted chat payload |
| 8 | PING | reserved |
| 9 | PONG | reserved |
| 10 | RATCHET | encrypted epoch update |
| 11 | HELLO | sender-boxed peer card, doubles as a punch |
| 12 | PUNCH | reserved |

An ACK uses the acknowledged message id as its own header message id, has a
zero session id and an empty payload.

### Sender boxes

HELLO, CHAT_REQUEST and CHAT_ACCEPT use:

```
sender_public_key[32] | crypto_box_easy(recipient, sender_sk, plaintext)
```

`crypto_box_easy` output begins with its random 24-byte nonce. This lets the
recipient identify the claimed sender and verify ownership of the X25519 secret
by successful authentication. The plaintext contains the claimed username and
Ed25519 signing key.

## 3. Discovery

### 3.1 Invite codes

A contact invite is `jn1:` followed by unpadded base64url of a MessagePack map:

```
v=1, t="c", n=username, pk=32B, spk=32B, ep=[ "ip:port", ... ], rv="host:port"
```

`ep` are endpoint hints (usually LAN addresses, loopback, and an explicit
advertise value). `rv` is the rendezvous service, if any. The code is public
information and is meant to be exchanged out of band.

### 3.2 Rendezvous service

The service is a UDP tag matcher. It receives only:

```
"JNRV1" | msgpack
```

Requests:

- `{"t":"reg","tag":bin16,"ttl":u32,"id":u64}` registers the observed source
  endpoint under an opaque tag.
- `{"t":"unreg","tag":bin16,"id":u64}` removes it.
- `{"t":"lookup","tag":bin16,"id":u64}` returns other endpoints under the tag.

Responses:

- `{"t":"peers","id":u64,"eps":[{"h":str,"p":u16}, ...]}`
- `{"t":"ok","id":u64}` / `{"t":"err","id":u64,"msg":str}`

Entries expire (default 120 seconds, capped at 600). The server applies per-IP
rate limits, caps endpoints per tag and the total tag count, and never logs IP
addresses. It
cannot decrypt anything and never receives public keys, usernames, session ids
or content.

A peer's tag for a UTC day is:

```
BLAKE2b-256("jargonet/rendezvous-tag/v1" | msgpack({d: day, k: public_key}), 16)
```

Peers register yesterday/today/tomorrow and look up today's tag, tolerating
clock skew and midnight boundaries. The tag is a rotating pseudonym (linkable
within a day), not a key.

### 3.3 Hole punching and presence

After learning candidate endpoints, a peer sends a sender-boxed HELLO to each
of up to three endpoints. A HELLO contains version, signing key, username,
relay capability and local port. Receiving a valid HELLO proves the sender's
X25519 secret, records the observed source endpoint, and triggers a HELLO reply
if none was sent in the last five seconds. These HELLOs are the hole-punch
probes; keepalives repeat every 20 seconds. A peer is shown online for 90
seconds after the last authenticated packet.

Unknown senders are accepted as contacts on a trust-on-first-use basis. A chat
request still requires explicit acceptance.

STUN (RFC 5389 binding request) is optional; its result is used only for invite
endpoint hints, not for identity or registration.

## 4. Session establishment

Initiator A:

1. Generates ephemeral X25519 key pair `EA`.
2. Sends CHAT_REQUEST with a sender box containing `{v, spk, n, eph=EA_pk}`.

Responder B:

1. Generates ephemeral `EB`.
2. Derives keys (below) and sends CHAT_ACCEPT with a sender box containing
   `{v, pk=B_pk, spk=B_spk, n, eph=EB_pk, sid}`.
3. Adds the active session immediately.

A verifies the accept, derives the same keys, compares the session id and only
then activates its side. The accept is authenticated by B's X25519 key through
`crypto_box`; a spoofed accept cannot produce a matching session id.

Key schedule:

```
shared  = X25519(self_ephemeral_sk, peer_ephemeral_pk)
(rx, tx) = crypto_kx_client_session_keys(A_pk, A_sk, B_pk)   # A
(rx, tx) = crypto_kx_server_session_keys(B_pk, B_sk, A_pk)   # B

i2r = BLAKE2b("jargonet/msg-i2r/v1" | client_tx | shared)
r2i = BLAKE2b("jargonet/msg-r2i/v1" | client_rx | shared)
sid = BLAKE2b("jargonet/session-id/v1" | i2r | r2i)[0..16]
```

The initiator sends with `i2r` and receives with `r2i`; the responder is the
reverse. The session id is opaque to observers, derived from secret keys, and
is therefore not linkable to either public key by someone without the keys.

Chat session setup requires direct reachability (rendezvous/hole punch). Once a
session exists, messages may use onion routing.

## 5. Chat payloads

`DIRECT` payload = `secretbox(epoch_key, msgpack)`. Plaintext fields:

```
sid, from (32B), spk (32B), name, text, seq, epoch, kind, msg (u64), sig (64B)
kind = "chat" | "join" | "member"
```

The Ed25519 signature covers a canonical MessagePack map of:
`sid, from, msg, seq, epoch, kind, text` (fixed field order). The receiver
checks:

- secretbox authentication using the current or previous epoch key;
- `sid` equals its session id;
- the header message id equals the signed `msg` (prevents replayed ciphertext
  under a new header id);
- the epoch is current or one behind while the previous-key window is open;
- for one-to-one sessions, `from` and `spk` equal the pinned peer values;
- the signature.

The receiver deduplicates by `(session id, message id)`. The text limit is 320
bytes so a five-relay onion fits in one datagram.

## 6. Ratchet

Only the session initiator is the ratchet leader. After 100 messages in either
direction or 24 hours (in-memory time), the leader:

1. Generates ephemeral key pair `R`.
2. Computes `dh = X25519(R_sk, peer_identity_pk)`.
3. Derives `new_i2r = BLAKE2b("jargonet/ratchet-i2r/v1" | i2r | dh | R_pk)` and
   similarly `new_r2i`.
4. Sends an encrypted RATCHET control (under the old send key) containing
   `{sid, from, epoch+1, R_pk}`.
5. On successful send, moves the old keys into a two-minute previous-key slot
   and installs the new epoch keys.

The responder authenticates the control with its old receive key, computes the
same DH with its identity secret, verifies the epoch is exactly current+1, and
rotates. Old ciphertexts are accepted only for that two-minute window and only
for the previous epoch. The ratchet provides coarse forward secrecy; it is not
a per-message double ratchet. Groups do not ratchet.

## 7. Onion routing

A sender chooses 3-5 online peers (uniformly random, excluding itself and the
recipient). The innermost layer is:

```
msgpack({t:"d", ip:str, pt:u16, d: delivered_packet_bytes})
```

It is sealed with `crypto_box_seal` to the last relay. Then, for each earlier
relay from last to first:

```
layer = msgpack({t:"r", ip:next_host, pt:next_port, d: sealed_next_layer})
sealed = crypto_box_seal(relay_public_key, layer)
```

The sender transmits the outer sealed bytes to the first relay as ONION_DATA
with `ttl = path length`. A relay attempts to open the payload with its own
secret key. On success:

- `r` layer: if `ttl > 0`, transmit the inner sealed bytes to `next` in a fresh
  ONION_DATA packet (new random session id/message id, `ttl-1`);
- `d` layer: transmit the inner packet bytes to the final endpoint.

Relays keep a ten-minute replay cache keyed by the hashed sealed payload. They
never see the sender's public key or the final recipient's address; only the
previous hop's source address and one next endpoint. The first relay sees the
sender's network address, and the delivery relay sees the recipient's network
address. The inner DIRECT packet's real session id is encrypted inside the
onion; intermediate relays see only random packet ids.

There is no end-to-end ACK for onion messages. Relays do not retransmit, and
the sender sends once. Recipients deduplicate; the UI labels these messages
`(via onion)` rather than claiming delivery confirmation.

## 8. Reliability

Direct chat packets, CHAT_REQUEST, CHAT_ACCEPT and RATCHET are retried at three
seconds, up to three sends, and complete on an ACK from the destination
endpoint. Chat requests remain pending for 60 seconds to allow the peer to
accept. ACKs are not encrypted; they reveal only a random message id and are
used solely to stop retransmission.

## 9. Groups

`/group` creates a random 16-byte session id and a random 32-byte group key,
then prints a `jng1:` base64url invite:

```
v=1, t="g", sid, key(32B), label, creator pk/spk/name, endpoints, rendezvous
```

The invite is a bearer credential: anyone who has it can read and send to the
group. Group messages use the single group key with the same signed payload
format. `join` sends a signed JOIN message to known members; receivers add
unknown senders that present a valid group-key ciphertext and signature. Group
fan-out targets every known member with a reachable endpoint. Group key
rotation, member authentication against a roster, and offline member discovery
are not implemented.

## 10. Limits and invariants

- Max datagram: 1200 bytes; max onion payload: 1142 bytes.
- Max chat text: 320 bytes.
- Session ids: 16 bytes from BLAKE2b; collisions are checked when creating
  groups.
- All keys and lengths are validated before use; low-order X25519 points are
  rejected.
- No packet is accepted with a bad magic, version, type, length, TTL or
  signature.
- Every chat plaintext is bound to its session id, sender key, message id,
  sequence, epoch and kind.
