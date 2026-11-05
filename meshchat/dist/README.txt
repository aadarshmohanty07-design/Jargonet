MESHCHAT - LAN onion-routing demo
================================

This bundle is self-contained. You do not need a compiler, a package manager,
MSYS2, or a GitHub account.

The demo has four roles on one WiFi network or hotspot:

  Alice  port 9001
  Bob    port 9002
  R1     port 9003
  R2     port 9004

All four use UDP 9999 for broadcast discovery. Each machine must have a unique
--port value.

Linux / macOS launch (four machines)
------------------------------------
  Machine 1: ./run.sh --name Alice --port 9001
  Machine 2: ./run.sh --name Bob   --port 9002
  Machine 3: ./run.sh --name R1    --port 9003
  Machine 4: ./run.sh --name R2    --port 9004

Windows launch (four machines)
------------------------------
  Machine 1: run.bat --name Alice --port 9001
  Machine 2: run.bat --name Bob   --port 9002
  Machine 3: run.bat --name R1    --port 9003
  Machine 4: run.bat --name R2    --port 9004

If you double-click run.sh or run.bat with no arguments, the binary starts with
a host-based default name and an ephemeral port. The commands above are the
recommended demo configuration.

Useful commands in every terminal:
  /peers
  /send Bob hi
  /send Bob --relays 2 hello through the mesh
  /quit

The peer list includes your own node as "(you, FINGERPRINT)". A relay prints
yellow [HOP ] [RELAY] lines with the forwarded hex. Only the recipient prints
the plaintext, prefixed with [RECV].

If the four do not appear in /peers
----------------------------------
1. Check the firewall. On Windows, run an Administrator PowerShell once:

   netsh advfirewall firewall add rule name="meshchat" dir=in action=allow protocol=UDP localport=9001-9004,9999

   On Linux with ufw:

   sudo ufw allow 9001:9004/udp
   sudo ufw allow 9999/udp

2. The access point may use client/AP isolation. Find each machine's address:
   Linux: ip -4 addr show
   Windows: ipconfig

   Then pass the other machines' unicast ports as explicit seeds. Every machine
   can use the same list; it is comma-separated and may include itself:

   Linux:
     ./run.sh --name Alice --port 9001 --peers 192.168.1.21:9002,192.168.1.22:9003,192.168.1.23:9004

   Windows:
     run.bat --name Alice --port 9001 --peers 192.168.1.21:9002,192.168.1.22:9003,192.168.1.23:9004

   Use each machine's own --port (9002, 9003, 9004), not 9999, in the seed
   list. The seeded nodes still use the normal onion/direct message path.

3. If Windows Smart App Control blocks this unsigned exe, use the Linux bundle
   on a laptop, or use a Windows machine where SAC is off. Do not disable SAC
   on a shared machine without permission. The Windows exe is unsigned; CI
   verifies it, but a local SAC policy can still refuse to launch it.

Diagnostics
-----------
The source repository includes check_demo.sh / check_demo.ps1, which check the
binary, UDP ports, loopback broadcast discovery and optional --peers seeds.
TROUBLESHOOTING.md in the repository covers the five common rehearsal failures.
