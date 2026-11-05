# Live demo runbook

Four roles: **Alice 9001**, **Bob 9002**, **R1 9003**, **R2 9004**. All use UDP
9999 discovery. Use four machines, or four windows on one machine.

## Before the clock starts

1. Use the bundle, or build the repo once. Both are offline after that.
2. Put all machines on the same WiFi/hotspot.
3. Run the preflight on each machine:
   - Linux: `./check_demo.sh --binary ./meshchat`
   - Windows: `.\check_demo.ps1 -Bin .\meshchat.exe`
   Expect green **READY**.
4. If the access point isolates clients, collect addresses (`ip -4 addr show` /
   `ipconfig`) and add `--peers` with each machine's unicast `--port`.
5. On Windows, run the firewall command from TROUBLESHOOTING.md once.

## The timed run

| Time | Action | Expected |
| --- | --- | --- |
| 0:00 | On machine 1: `./run_demo.sh` (Linux) or start one node per machine with the four commands in README.txt | Four terminals labeled Alice, Bob, R1, R2 |
| 0:10 | Type `/peers` in Alice | Cyan `Online:` line lists Alice (you), Bob, R1, R2 |
| 0:15 | Alice: `/send Bob hi` | Bob prints green `[RECV] [Bob] Alice: hi`; Alice prints `[sent] to Bob (direct)` |
| 0:25 | Alice: `/send Bob --relays 2 hello through the mesh` | Alice prints `[sent] ... via 2 relays` |
| 0:30 | Watch R1 and R2 | Both show yellow `[HOP ] [RELAY] ... forwarded <hex>`; neither shows the message text. Only Bob prints the plaintext. |
| 0:40 | R1: `/quit` (or close the R1 window) | R1 exits. `/quit` broadcasts BYE immediately; an abrupt close disappears after at most 10s. |
| 0:45 | Alice: `/peers` | R1 is gone; Alice, Bob and R2 remain |
| 0:50 | Alice: `/send Bob --relays 1 still works` | Alice prints a 1-relay send; Bob receives the plaintext |
| 0:55 | Bob's terminal | `[RECV] [Bob] Alice: still works` — demo complete |

Add `--verbose-route` to either send if you want the sender to print the full
path, e.g. `Alice -> R1 -> R2 -> Bob`.

## If it breaks

- **0:10 — Alice lists only herself.** Check that every node reports
  `discovery UDP 9999`; check the firewall; if the AP isolates clients, relaunch
  with `--peers`. Run `check_demo.sh`/`check_demo.ps1` again.
- **0:10 — Alice shows Bob but not R1/R2.** R1/R2 may still be starting; wait
  two seconds. Verify their terminals are on ports 9003/9004.
- **0:15 — Bob prints nothing.** Make sure the recipient is named exactly `Bob`
  (case-insensitive names resolve, but a typo does not), and that Bob is in
  Alice's `/peers`. If the direct path is firewalled, use `--relays 1` once R1
  is online.
- **0:25/0:30 — no `[HOP ]` at R1/R2.** Check that both are online in Alice's
  `/peers`; if the sender fell back to direct, the sender line says `(direct)`.
  A `--peers` list with wrong ports is the usual cause.
- **0:30 — a relay prints the message text.** That should be impossible; stop the
  demo and preserve that terminal. This is a security bug, not a demo glitch.
- **0:40 — R1 does not disappear.** Wait up to 10 seconds for the HELLO timeout.
  If it stays, check that the node you quit owns 9003, not 9001/9002.
- **0:50 — the second send fails.** Check that R2 is still in `/peers`; try
  `--relays 1` explicitly, or send directly with no relay flag.
- **Colors missing.** The terminal is not a TTY or lacks ANSI support; the text
  is still valid. Use a standard terminal on Linux, Windows Terminal/PowerShell
  7 on Windows.

## One-machine fallback

If four machines are not available, `run_demo.sh` opens all four roles in a
2×2 tmux grid on one Linux laptop; `run_demo.ps1` opens four PowerShell windows
on Windows. The same timed script applies. The demo still uses real UDP sockets,
real sealed crypto and real relay processes.
