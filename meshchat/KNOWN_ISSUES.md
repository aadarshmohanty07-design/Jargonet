# Known issues and scope

This is a LAN demo prototype for a fixed deadline. These are known and
intentionally not changed this week.

- **Physical hardware is unverified by the developer.** CI runs six real
  processes on Ubuntu and Windows over loopback broadcast, and all pass; the
  first real WiFi/hotspot rehearsal is still yours. Use `check_demo.sh` /
  `check_demo.ps1`, the firewall commands and the `--peers` fallback.
- **No sender authentication.** Direct and onion payloads are
  `crypto_box_seal`; a sealed box hides content but does not prove who sent it.
  HELLO and BYE are plaintext and unauthenticated. A peer can claim any display
  name inside a sealed payload. The full Jargonet protocol, not this demo,
  provides authenticated sessions.
- **Relay visibility.** A relay sees the previous and next endpoint, packet
  size/timing and the forwarded ciphertext. The first relay sees the sender's
  IP; the last relay sees the recipient's IP. There is no cover traffic or
  timing defense.
- **No delivery acknowledgement.** Chat packets are single UDP datagrams. A
  dropped datagram is dropped. The six-node smoke test runs over loopback where
  loss is rare; a busy WiFi network can lose a message.
- **Duplicate names exit one node.** The node with the larger public key prints
  `[fatal] duplicate peer name` and exits; the other remains. This is a local
  tie-break, not part of the wire protocol. Use unique names.
- **Self is display-only.** `/peers` prepends your own node as
  `(you, FINGERPRINT)` so the operator can confirm identity. Sending to yourself
  is not supported; the routing peer map contains only other nodes.
- **Discovery is limited broadcast plus loopback broadcast.** AP/client
  isolation and some VPN adapters (for example WARP) can prevent it. Use the
  explicit `--peers ip:port,...` fallback; use each machine's unicast `--port`,
  not 9999.
- **Port 9999 is shared and required for discovery.** A non-reusing application
  holding it prevents normal startup. `--peers` plus `--no-broadcast` can run
  without it, but both ends need seeds.
- **Message limits.** Text is capped at 700 bytes and onion paths at four
  relays so a message fits comfortably in a UDP datagram. Longer messages print
  a red "[not sent]" error and are not truncated silently.
- **Unsigned Windows executable / Smart App Control.** A local SAC policy may
  refuse the exe. Use the Linux bundle or a Windows machine where SAC is off;
  do not disable SAC on a shared machine for the demo. The Windows CI runner
  executes the same code.
- **Windows bundle may contain DLLs.** The packaging script copies non-system
  imports; a fully static MinGW build needs none. Verify on the demo machine by
  launching `run.bat` once during rehearsal.
- **Not in scope:** sessions, ratchet, DHT, NAT traversal, STUN, group chat,
  invitations, Android/iOS, identity authentication, cover traffic and any
  change to the onion/crypto/wire format.

If a new bug appears during rehearsal, write it here and do not change the
protocol to fix it. Workaround first; fix after the demo.
