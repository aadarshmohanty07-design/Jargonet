# meshchat

A standalone, one-binary LAN prototype for real UDP broadcast discovery, sealed
messages and onion routing through whichever peers are online. No DHT, no NAT
traversal, no sessions, no group chat, and no hardcoded peer table.

It lives in the Jargonet repository but is its own CMake project and compiles one
executable. It reuses only the libsodium wrapper, MessagePack codec and UDP
socket primitives from the parent project.

```
                    UDP broadcast :9999
   Alice  <-------------------------------->  Bob
     |                                         ^
     | sealed onion                            | direct sealed payload
     v                                         |
   Relay1  --------- opaque blob --------->  Relay2
```

## Build

```bash
# Debian/Ubuntu
sudo apt install cmake ninja-build g++ libsodium-dev

# macOS
brew install cmake ninja libsodium

cmake -S meshchat -B meshchat/build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build meshchat/build -j
```

On Windows, use vcpkg or MSYS2 libsodium, or point the build at a prefix:

```bash
cmake -S meshchat -B meshchat/build -G Ninja -DJARGONET_SODIUM_ROOT=C:/path/to/libsodium-win64
cmake --build meshchat/build -j
```

The Windows build prefers the static libsodium and links the MinGW runtime
statically, so the exe is self-contained. Output: `meshchat/build/meshchat`
(`meshchat.exe` on Windows).

## Run

Use a different unicast port for every instance. All instances share discovery
port 9999.

```bash
./meshchat/build/meshchat --name Alice  --port 9001
./meshchat/build/meshchat --name Bob    --port 9002
./meshchat/build/meshchat --name Relay1 --port 9003
./meshchat/build/meshchat --name Relay2 --port 9004
```

Each instance broadcasts a plaintext HELLO (`name`, `pubkey`, `unicast port`) to
`255.255.255.255:9999` every two seconds and listens on `:9999` with address
reuse. Peers expire after 10 seconds without a HELLO. A clean `quit` broadcasts
and unicasts a BYE, so the peer disappears immediately.

Four terminals are enough to show onion routing. Six or more show the same
peer list and routing behavior at larger sizes. `meshchat/run_demo.sh` opens
four panes in tmux; `meshchat/run_demo.ps1` opens four Windows console windows.

## Commands

| Command | Meaning |
| --- | --- |
| `send <name> <message>` | Direct sealed UDP message |
| `send <name> <message> --relays 2` | Route through two online peers |
| `send <name> <message> --relays 2 --verbose-route` | Also print the full path |
| `peers` | Reprint the online peer list |
| `quit` | Broadcast BYE and exit |

If the requested number of relays is unavailable, the sender uses as many as
are online. If none are online, it sends directly. Every node relays
automatically; there is no relay opt-in.

Names are 1-24 characters of letters, digits, `_` or `-`. If two peers share a
name, use a fingerprint prefix instead:

```
send 3FA9C1B2 hello
```

## What you see

- Cyan: live peer list, send confirmation, route.
- Yellow: a relay forwarding a packet, or a notice.
- Green: a decrypted message at the recipient.
- Red: errors.
- Gray: the hex of every data packet received (the ciphertext, before
  decryption) and command help.

The peer list is printed whenever membership changes, and with `peers`:

```
Online: Bob (7C13A9F2), Relay1 (9C110A3D), Relay2 (B3D01F22)
```

A relay prints both the received sealed bytes and the opaque payload it
forwards:

```
[RELAY] received 412 bytes from Alice -> next Relay2 (192.168.1.24:9004) | forwarded 7f2c...
```

Only the final recipient prints the plaintext:

```
[Bob] Alice: hi
```

There is no plaintext in a relay's terminal. The sender can print the route
with `--verbose-route` for the audience:

```
Alice -> Relay1 -> Relay2 -> Bob
```

## How the onion works

The sender chooses up to four online peers, excluding itself and the recipient,
and builds the payload from the inside out:

1. `crypto_box_seal(recipient_pubkey, message)` — only Bob can open it.
2. A layer for the last relay: `{next: Bob, type: direct, inner: sealed_message}`,
   sealed to that relay's pubkey.
3. A layer for each earlier relay: `{next: next_relay, type: onion, inner:
   previous_sealed_layer}`, sealed to that relay's pubkey.

The outer sealed layer is sent to the first relay as an `ONION` UDP packet. A
relay decrypts exactly one layer, prints the forwarded blob's hex, and sends the
inner blob to the next endpoint. The last relay sends a `DIRECT` packet
containing the recipient-sealed payload. The recipient decrypts with its own
secret key.

The packet header carries a small hop limit so a malformed loop cannot run
forever. The payload length is bounded; chat text is capped at 700 bytes.

## Discovery fallback

If broadcast does not cross the access point (AP isolation, client isolation,
or a host firewall), add unicast seeds using each peer's `--port` value:

```bash
./meshchat/build/meshchat --name Alice --port 9001 \
  --peers 192.168.1.22:9002,192.168.1.23:9003
```

A seeded instance sends a HELLO to the other peer's unicast port; that peer
replies with its HELLO, so discovery works in both directions. The seeds are
retried every two seconds.

If port 9999 cannot be bound at all, a node with `--peers` still starts and uses
manual discovery only.

Windows: allow inbound UDP for the chosen unicast port and 9999 on the private
network. The first launch may show a firewall prompt. If WARP/VPN or a second
adapter changes the broadcast source address, use `--peers` with the actual LAN
addresses.

## Acceptance demo

1. Build and start Alice, Bob, Relay1 and Relay2 in four terminals.
2. Wait for every terminal to print all four names in `Online:`.
3. In Alice: `send Bob hi` → only Bob prints `[Bob] Alice: hi`.
4. In Alice: `send Bob hi --relays 2 --verbose-route` → Relay1 and Relay2 print
   yellow `[RELAY]` lines with opaque hex blobs and forward; Bob prints the
   message; neither relay contains `hi` in its output.
5. In Relay1: `quit`. Wait for Alice's peer list to drop Relay1 (immediate via
   BYE; at most 10 seconds after an abrupt kill).
6. In Alice: `send Bob after-kill --relays 2` → Bob receives it through the
   remaining online peers.
7. Start Relay3 and Relay4 too: all six instances should list all five others.

`python3 meshchat/tests/smoke.py meshchat/build/meshchat` automates the six-node
version, including discovery, direct and onion messaging, relay blindness,
dead-peer removal and post-kill delivery. CI runs it on Linux, and the Windows
CI job builds the exe and runs the same smoke test.

## Security scope

- **Confidentiality:** message payloads and onion layers use libsodium
  `crypto_box_seal` (X25519 + XSalsa20-Poly1305).
- **Relay blindness:** each relay can open exactly one layer; the forwarded blob
  and the final message are opaque to it.
- **Relay visibility:** a relay sees the immediate previous hop's endpoint, the
  next endpoint, packet timing/size and the forwarded ciphertext. The first
  relay sees the sender's IP; the last relay sees the recipient's IP. There is
  no cover traffic or timing defense.
- **No sender authentication:** sealed boxes are anonymous. A peer can claim any
  display name in the sealed plaintext; HELLOs and BYEs are plaintext and
  unauthenticated. This prototype demonstrates content privacy and multi-hop
  forwarding, not a full identity/session protocol. Do not use it for hostile
  LANs or high-stakes identity decisions.
- **Trust on the LAN:** anyone who can send a HELLO can appear in the peer list;
  a spoofed BYE can remove a displayed peer. The full Jargonet protocol is the
  place for authenticated sessions.
- **No persistence:** each launch creates a fresh X25519 key. Names are labels,
  not unique ids; fingerprints disambiguate.
- **UDP only:** no acknowledgement or retransmission for chat datagrams. On a
  healthy LAN this is fine; a dropped datagram is dropped.
- **Not implemented here:** NAT traversal, DHT, offline delivery, sessions,
  groups, key rotation, Android/phone UI. Those belong to the larger Jargonet
  project; this is the transport-level demonstration.

## Source layout

```
meshchat/
  CMakeLists.txt
  src/mesh_node.{hpp,cpp}   discovery, peer table, direct and onion transport
  src/main.cpp              colored CLI, command parser
  tests/smoke.py            six real processes over loopback broadcast
  run_demo.sh, run_demo.ps1 four-terminal demo launchers
```
