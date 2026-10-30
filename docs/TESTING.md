# Testing and verification

## Automated suite

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build
ctest --test-dir build --output-on-failure
```

CI runs this on Ubuntu and on Windows (MSYS2 UCRT64). The suite has no network
dependencies and uses loopback ports.

| Test | Coverage |
| --- | --- |
| `test_crypto` | box/secretbox/sealed-box round-trips, tamper rejection, key validation, `crypto_kx`, ephemeral DH agreement, Ed25519, Argon2id, encodings |
| `test_msgpack` | canonical round-trips, width variants, truncation/trailing/nesting limits |
| `test_packet` | exact header layout, all types, TTL/size/magic rejection |
| `test_identity` | encrypted identity at rest, unlock, wrong password, corruption, wipe |
| `test_store` | encrypted contacts/sessions/messages, no plaintext leakage, wrong password, wipe |
| `test_onion` | 3- and 5-hop construction, per-hop isolation, tamper and oversize rejection, path-selection constraints |
| `test_session` | handshake agreement, message signatures and field binding, epoch/ratchet behavior, group key, invite round-trips |
| `test_rendezvous` | registration/lookup, tag rotation, invalid tags, expiry bookkeeping, STUN response parsing |
| `test_integration` | five loopback nodes: full-mesh HELLOs, direct chat, three-relay onion delivery, relay content isolation, group join/send, panic wipe |

The integration test is the important one: it asserts that a three-hop path
actually relays a message, that the two intermediate relays and the delivery
relay only gain one hop of information, that the delivery relay sees a
non-recipient source, and that the plaintext never appears at a relay. It also
checks that all five nodes discover each other, that a session handshake
completes, that direct replies work after an onion-delivered message, and that
group invites and fan-out work.

## Manual verification on real networks

You need three or more hosts to see onion routing; two hosts can only use a
direct path.

1. On a public host, run `jargonet-rendezvous --port 47400` and allow UDP 47400.
   It needs no account and stores only expiring tags/endpoints.
2. On each peer, run `jargonet start --rendezvous <host>:47400 --port <p>`.
   Exchange contact invites out of band and `/add` them.
3. Confirm `/peers` shows all expected peers online. `/stats` shows counters but
   never endpoints or message content on the service side.
4. Establish one-to-one chats with `/chat` and `/accept`. With at least three
   other online peers, `auto` uses onion routing; `/msg` prints
   `sent via N relays`. With `/mode onion` it fails rather than silently
   downgrading when there are fewer than three relays.
5. Watch a relay terminal: it prints no chat text for messages it forwards.

### NAT matrix

| Topology | Expectation |
| --- | --- |
| No NAT / same LAN | HELLOs create direct reachability immediately. |
| Full-cone or restricted-cone NAT | STUN/rendezvous endpoint hints plus simultaneous HELLOs usually produce a direct tunnel. |
| Symmetric NAT on one side | Direct punching may fail. If a session was established, messages can still use onion relays; there is no TURN service. |
| Symmetric NAT on both sides | Often no direct tunnel. Onion relaying needs a reachable relay common to both peers and a previously established session; otherwise chat is unavailable. |

There is no automated NAT-topology simulator in this repository. The code
exposes STUN parsing and hole-punch behavior through testable components, but
the matrix above is a manual procedure. Report results with the OS, NAT type
and `/stats` output; do not include IP addresses in public reports.

### Windows Application Control

A local unsigned build may be refused by Smart App Control even when CI passes.
That is an OS code-integrity policy, not a build failure. Use a signed release,
a machine without that policy, or CI results. Do not weaken system security
settings just to run an alpha build.

## Security review checklist

- Every network length is bounded before allocating; every map/array has a cap.
- Keys are length-checked; low-order X25519 points are rejected.
- A relay can open exactly one onion layer; the unit test asserts that it cannot
  open the next layer.
- Chat signatures bind session id, sender, message id, sequence, epoch, kind and
  text; header message-id tampering is rejected.
- No server logs IP addresses; the rendezvous service has no content or key
  fields in its protocol at all.
- Local storage contains no timestamps, IPs, relay paths or session keys.
- Panic wipe overwrites and removes identity/store files, with the SSD caveat in
  `SECURITY.md`.
