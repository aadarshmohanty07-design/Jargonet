# Jargonet

[![ci](https://github.com/aadarshmohanty07-design/Jargonet/actions/workflows/ci.yml/badge.svg)](https://github.com/aadarshmohanty07-design/Jargonet/actions/workflows/ci.yml)

Private, accountless peer-to-peer chat for the desktop. There is no sign-up, no
email, no phone number, and no server-held identity. Your X25519 public key is
your network identity; a local username is just a label.

> **Status: early alpha, not audited.** Jargonet is a working protocol
> implementation with unit and integration tests, but it has not received an
> independent security review. Do not rely on it for high-risk work yet. See
> [docs/SECURITY.md](docs/SECURITY.md) for the exact threat model and known
> limitations.

## What works

- Local identity: username + password, Argon2id-derived key, encrypted X25519
  private key on disk.
- Optional zero-knowledge rendezvous service that sees only rotating opaque
  tags and UDP endpoints, never keys, usernames or messages.
- STUN discovery, invite-based peer introduction, UDP hole punching and
  keepalives.
- X25519 `crypto_kx` + ephemeral-DH session establishment, signed chat
  messages, and an X25519 key ratchet for one-to-one sessions.
- Layered onion routing through 3-5 peers for chat messages; every relay can
  open exactly one layer.
- Direct encrypted UDP chat with ACK/retransmit, used when fewer than three
  relays are online.
- Encrypted local history and contacts (libsodium secretbox), with no stored
  timestamps, IP addresses or relay paths.
- Group sessions shared as a bearer "session key" invite.
- Panic wipe of identity and local data.
- CLI for Windows, Linux and macOS; CMake build.

## Build

Requirements: CMake 3.20+, a C++20 compiler, and libsodium.

```bash
# Debian/Ubuntu
sudo apt install cmake ninja-build g++ libsodium-dev

# macOS
brew install cmake ninja libsodium

# Windows with vcpkg
vcpkg install libsodium
```

Then:

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

If libsodium is in a custom prefix:

```bash
cmake -S . -B build -DJARGONET_SODIUM_ROOT=/path/to/libsodium
```

On Windows the project links MinGW runtimes statically when built with MinGW,
so the resulting `jargonet.exe` does not depend on a particular libstdc++ DLL
being first on `PATH`. Windows Application Control (Smart App Control) may
refuse to launch an unsigned local build; that is an OS policy, not a build
failure. CI builds and tests on both Ubuntu and Windows.

### Windows libsodium note

The official libsodium release ships a MinGW static build. Point CMake at it:

```bash
cmake -S . -B build -G Ninja -DJARGONET_SODIUM_ROOT=C:/path/to/libsodium-win64 -DSODIUM_LIBRARY=C:/path/to/libsodium-win64/lib/libsodium.a
```

## Quick start (same machine, two peers)

Terminal 1, start the rendezvous service (optional, but useful for discovery):

```bash
./build/jargonet-rendezvous --port 47400
```

Terminal 2:

```bash
./build/jargonet init --name alice --data-dir .demo/alice
./build/jargonet start --data-dir .demo/alice --port 41001 \
  --rendezvous 127.0.0.1:47400
```

Terminal 3:

```bash
./build/jargonet init --name bob --data-dir .demo/bob
./build/jargonet start --data-dir .demo/bob --port 41002 \
  --rendezvous 127.0.0.1:47400
```

In each terminal run `/invite` and paste the printed `jn1:` code into the other
peer with `/add <code>`. Wait for each other to show online with `/peers`, then:

```
alice> /chat bob
bob>   /accept alice
alice> /msg hello
```

With only two online peers there is no relay path, so messages use direct
encrypted UDP. Start four or five nodes (or use `--mode onion` once enough peers
are online) to see the `sending via N relays` path.

> **No recovery.** The password protects the local key; nobody can reset it.
> Lose the password or the data directory and the identity is gone.

## CLI

| Command | Meaning |
| --- | --- |
| `/whoami` | Username, fingerprint, invite |
| `/invite` | Contact invite code (contains your public key and endpoint hints) |
| `/add <code>` | Add a peer |
| `/peers` | Known peers and online state |
| `/chat <peer>` | Send a chat request |
| `/requests`, `/accept`, `/decline` | Manage incoming requests |
| `/sessions`, `/open <id>` | List and select conversations |
| `/msg <text>` or plain text | Encrypt and send to the selected conversation |
| `/history [n]` | Local history |
| `/group <label>` | Create a group and print its bearer invite |
| `/join <invite>` | Join a group with a shared session key |
| `/ginvite` | Reprint the selected group invite |
| `/mode auto\|direct\|onion` | Routing policy |
| `/stats` | Local routing counters |
| `/wipe WIPE` | Destroy identity and local history |

## Architecture

| Module | Responsibility |
| --- | --- |
| `CryptoEngine` | libsodium wrapper: box, secretbox, sealed box, `crypto_kx`, Argon2id, BLAKE2b, Ed25519 |
| `IdentityManager` | Password-encrypted local identity, fingerprints |
| `UdpSocket` / `RendezvousServer` | Non-blocking UDP and the tag-matching service |
| `RendezvousClient`+`Node` discovery | Tags, STUN, invite endpoints, hole-punch HELLOs, keepalives |
| `SessionManager` | Session derivation, epoch keys, ratchet, persistence of metadata |
| `MessageDispatcher` | Chat payload encryption, signatures, direct/onion packet construction |
| `OnionRouter` | Sealed-box layers, path selection, peel/forward |
| `LocalStore` | Argon2id + secretbox encrypted contacts, sessions, messages |
| `Node` | Event loop, peer table, reliability, rendezvous, relay role, group fan-out |
| `ConsoleApp` | CLI |

More detail: [docs/PROTOCOL.md](docs/PROTOCOL.md),
[docs/SECURITY.md](docs/SECURITY.md) and [docs/TESTING.md](docs/TESTING.md).

## Protocol at a glance

- Wire packets: `JGN1 | version | type | flags | ttl | session id | msg id |
  nonce | length | payload`, maximum 1200 bytes over UDP.
- Chat handshake: authenticated sender box carrying an ephemeral X25519 key.
  Both sides derive directional keys from `crypto_kx` mixed with the ephemeral
  DH and confirm a session id.
- Messages: `crypto_secretbox` under the epoch key, with an Ed25519 signature
  binding session, sender, message id, sequence, epoch and text.
- Onion: innermost delivery layer plus one `crypto_box_seal` layer per relay.
  A relay decrypts one layer, learns one next endpoint, forwards opaque bytes.
- Ratchet: the session initiator rotates the epoch with a fresh X25519 key
  every 100 messages or 24 hours. A short previous-key window handles in-flight
  packets.
- Discovery: daily rotating `BLAKE2b(public key, day)` tags at a rendezvous
  service, plus direct invite endpoint hints; peers then exchange encrypted
  HELLOs that serve as hole-punch probes.
- Storage: no timestamps, IPs or relay paths are persisted.

## Security posture

Jargonet protects message content and gives relays only one hop of visibility.
It does **not** provide anonymity against a global network observer, and it is
not a replacement for Signal's double ratchet or Tor. The first relay sees the
sender's IP; the final relay sees the recipient's IP; timing and packet sizes
are observable. The rendezvous service sees rotating pseudonymous tags and IP
addresses. See [docs/SECURITY.md](docs/SECURITY.md) for the full list.

## Tests

`ctest` runs:

- crypto round-trips, tamper rejection, `crypto_kx` agreement, signatures,
  Argon2id, key validation;
- MessagePack, packet framing and size/TTL validation;
- identity and store encryption, wrong-password rejection, wipe;
- onion layer isolation (a relay cannot open another hop's layer);
- session handshake, signature binding, ratchet and group-key behavior;
- rendezvous registration/lookup and STUN parsing;
- a five-node loopback integration test covering full-mesh discovery, direct
  chat, a three-relay onion message, relay isolation, group join/send and panic
  wipe.

## Not implemented yet

- Full Kademlia DHT (the rendezvous service is the lightweight substitute).
- TURN/relay pools operated by third parties; relays are online peers.
- Offline message delivery (content is never queued server-side).
- Persistence of live session keys across restarts; re-establish the chat.
- Persistence of peer endpoints (by design, to avoid storing IP addresses). After
  a restart, use a rendezvous server or re-add the peer's invite.
- Automated simulation of full-cone/symmetric NAT topologies; see the manual
  matrix in [docs/TESTING.md](docs/TESTING.md).
- Per-message forward secrecy (the epoch ratchet is coarse) and cover traffic.
- A GUI. The CLI is the supported interface.

## License

MIT. See [LICENSE](LICENSE).
