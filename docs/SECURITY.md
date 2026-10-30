# Security model

Jargonet is an early-alpha, accountless chat protocol. This document is
deliberately explicit about what it does and does not protect. It has not been
independently audited.

## Goals

- Message content is readable only by session participants.
- A relay cannot decrypt message content.
- A single relay does not learn both endpoints of a conversation.
- The rendezvous service cannot learn identities, public keys, session ids or
  message content.
- Local secrets are encrypted at rest under a password-derived key.
- Chat history contains no timestamps, IP addresses or relay paths.
- Identity loss is irreversible and there is no server-side account to recover.

## Non-goals

- Anonymity against a global passive adversary.
- Resistance to traffic analysis, timing correlation or packet-size analysis.
- Hiding that two IP addresses exchange encrypted UDP packets in direct mode.
- Hiding the sender's IP from the first relay or the recipient's IP from the
  final relay.
- Deniability, cover traffic, dummy messages or traffic shaping.
- Protecting a device that is already compromised while the app is unlocked.
- Surviving loss of the password or the local data directory.

## Threat model and observability

| Party | Learns | Does not learn |
| --- | --- | --- |
| Rendezvous service | Rotating 16-byte tags, source endpoints, requested tags | Public keys, usernames, session ids, content, social graph |
| First onion relay | Sender's network address, next hop endpoint | Recipient, session id, content |
| Middle relay | Previous and next hop endpoints | Sender, recipient, session id, content |
| Delivery relay | Previous hop, recipient endpoint | Sender, session id (inner packet is opaque), content |
| Direct-mode network observer | Two endpoint addresses, packet timing/size | Content, session id meaning |
| A malicious contact | Messages sent to it, its own keys | Other peers' private keys |
| Server operator logs | Nothing by default; the service never logs IPs | Keys/content |

The rendezvous tag is `BLAKE2b(public key, UTC day)`. It is a pseudonym that
rotates daily and is linkable within a day by someone who sees the tag and can
guess the public key (public keys are not secret). The service never receives
the key itself.

## Cryptography

- X25519 (`crypto_box`) identity keys and anonymous `crypto_box_seal` for onion
  layers.
- `crypto_kx` over identity keys mixed with an ephemeral X25519 DH for session
  keys. `crypto_secretbox` (XSalsa20-Poly1305) for chat payloads.
- Ed25519 signatures bind session id, sender key, message id, sequence, epoch,
  kind and text. The signing key is included in the encrypted payload and is
  authenticated for direct sessions by the session handshake and signature
  pinning.
- Argon2id (`crypto_pwhash`) derives local encryption keys. Salts and KDF
  parameters are stored with the ciphertext. The default is libsodium's
  interactive setting; tests use reduced parameters.
- BLAKE2b derives fingerprints, tags and subkeys.
- `randombytes_buf` provides nonces and ids. Secretbox nonces are random
  24-byte values; the probability of collision is negligible for the data
  volumes supported.
- Public keys are length-checked and probed against low-order X25519 points.
  Malformed packets, lengths, versions and TTLs are rejected before use.

## Forward secrecy

One-to-one sessions rotate epoch keys through an X25519 ratchet every 100
messages or 24 hours. Old keys are retained for at most two minutes to accept
in-flight packets, then wiped. This limits exposure of past traffic after a
device compromise, but it is **not** a Signal-style per-message double ratchet:
a compromised live session can read messages in that epoch, and identity-key
compromise aids future ratchet steps. Group sessions share one static key and
have no forward secrecy; rotate by creating a new group invite. A RATCHET
control that is lost after all retransmits can desynchronize the epoch; the
peers must re-establish the chat in that case.

## Local storage

- Identity private keys are sealed with a password-derived Argon2id key.
- Contacts, session metadata and messages are in a separate encrypted container.
- The live session keys are memory-only and are not persisted. Restarting loses
  the session; history remains readable and a new handshake is required.
- No timestamps, IP addresses, relay paths or endpoints are written to the
  store. Endpoints exist in memory for reachability only.
- Password input is hidden on a TTY and the password string is wiped after use.
  Secret key buffers are allocated with `sodium_malloc`, wiped on rotation and
  destruction, and the store key is wiped when the store closes.
- Memory wiping is best-effort: strings in earlier allocations, crash dumps,
  hibernation files and the OS pagefile are outside the app's control.

### Panic wipe

`/wipe WIPE` closes sockets, wipes identity and store keys, destroys the store
object, overwrites files with zeros where possible, unlinks them and exits.
Flash storage, copy-on-write filesystems, filesystem journals, snapshots and
backups may retain old blocks. A panic wipe is not a cryptographic guarantee
against forensic recovery of the physical device.

## Peer identity and trust

- There is no certificate authority, global directory, account recovery or
  password reset.
- A contact is identified by the X25519 public key and its fingerprint. The
  Ed25519 signing key is bound to that identity through the authenticated
  handshake and pinned on first use. If a peer changes its signing key, chat
  verification fails for one-to-one sessions and the session must be rebuilt.
- Unknown HELLOs are accepted as contacts (trust on first use), because anyone
  who knows your public key can send a punch. Chat requests still require
  explicit acceptance.
- A malicious peer can send a chat request claiming an arbitrary username; the
  fingerprint is the identity. Verify fingerprints out of band for high-risk
  contacts.
- Group membership is possession of the bearer invite. Anyone with the invite
  can read and send, and can introduce a new signing key for a new sender
  public key. There is no roster consensus or key rotation. Do not use groups
  for adversarial membership.

## Relay and network limitations

- Onion routing hides both endpoints from any single relay, but the first relay
  sees the sender's IP and the last relay sees the recipient's. A colluding
  first/last relay pair, or an ISP observing both ends, can link the
  conversation. There is no mixing, delay or cover traffic.
- Relays can drop, delay or replay onions. Replays are cached at relays, and
  recipients deduplicate, but a relay can still cause denial of service.
- Onion messages have no end-to-end delivery receipt. The UI says "sent via N
  relays", not "delivered". A direct-mode message is retried and ACKed;
  onion-mode messages are sent once.
- Direct mode exposes the two endpoints and confirms traffic activity. Auto
  mode uses direct when fewer than three relays are online. The CLI labels the
  chosen path after sending; use `/mode onion` to require relays (and accept
  failure when too few peers are online).
- NAT traversal is best-effort: STUN, invite endpoint hints and simultaneous
  sender-boxed HELLOs. There is no TURN or guaranteed relay rendezvous. Symmetric
  NATs may fail; two peers behind restrictive NATs may never establish a direct
  tunnel.
- Session establishment itself requires direct reachability. Onion routing is
  used for messages after a session exists.
- UDP offers no source authentication by itself; authenticated packets are
  sender-boxed, signed, or sealed. ACKs are unauthenticated and only stop
  retransmission. Spoofed ACKs can cause a message to be considered sent.
- DoS: the network-facing code bounds packet sizes, fragment counts, nesting
  depth and replay caches. A determined peer can still flood bandwidth or fill
  the friend requests list; there is no proof-of-work or global rate limit in
  the client.

## Cryptographic choices not to change casually

- The public key encrypts to the recipient; the private key decrypts. Session
  messages use a symmetric shared key derived from both ephemeral DH and
  `crypto_kx`; do not invert these roles.
- Each onion layer must be independently sealed to one relay. A single shared
  encryption layer provides no relay isolation.
- The session id must be derived from secret material, not from a monotonic
  counter, and must not be stored on a server.
- Message ids and epochs are inside the signature; that binding is what makes
  header tampering and replay detection effective.

## Reporting

This is an early-stage project without a bug bounty. If you find a
vulnerability, open a private security advisory on the repository rather than a
public issue with exploit details. Provide a reproduction and the affected
version. Do not test against other people's deployments or devices without
authorization.
