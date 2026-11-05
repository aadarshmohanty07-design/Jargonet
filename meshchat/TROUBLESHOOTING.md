# Rehearsal troubleshooting

Run `./check_demo.sh` (Linux/macOS) or `.\check_demo.ps1` (Windows) first. It
reports `READY` or `NOT READY: <reason>`. The fixes below are the five failures
that show up during rehearsal.

## 1. Windows firewall prompt or silent drop

Allow the four unicast ports and the discovery port once in an Administrator
PowerShell:

```powershell
netsh advfirewall firewall add rule name="meshchat" dir=in action=allow protocol=UDP localport=9001-9004,9999
```

If your `netsh` build rejects the range, add two rules:

```powershell
netsh advfirewall firewall add rule name="meshchat-unicast" dir=in action=allow protocol=UDP localport=9001-9004
netsh advfirewall firewall add rule name="meshchat-discovery" dir=in action=allow protocol=UDP localport=9999
```

Check the rule:

```powershell
netsh advfirewall firewall show rule name="meshchat"
```

Make sure the WiFi/hotspot network profile is Private, not Public. A silent
`/peers` that only shows yourself is the usual symptom.

## 2. Linux firewall

```bash
sudo ufw allow 9001:9004/udp
sudo ufw allow 9999/udp
sudo ufw status
```

If `ufw` is inactive, your distribution firewall may be `firewalld`; allow the
same UDP ports there. Two nodes on the same host can still work locally even
when the LAN firewall blocks other machines.

## 3. AP / client isolation

Symptom: two laptops on the same WiFi never list each other in `/peers`, even
after the firewall rules. Confirm client isolation by checking whether one
machine can reach the other at all:

```bash
ping <other-ip>
```

If ICMP is blocked too, the access point is probably isolating clients. Get the
addresses first:

Linux:

```bash
ip -4 addr show
hostname -I
```

Windows:

```powershell
ipconfig
```

Then launch every node with an explicit seed list. Use each machine's own
unicast `--port`, not 9999:

Linux:

```bash
./run.sh --name Alice --port 9001 --peers 192.168.1.21:9002,192.168.1.22:9003,192.168.1.23:9004
./run.sh --name Bob   --port 9002 --peers 192.168.1.20:9001,192.168.1.22:9003,192.168.1.23:9004
```

Windows:

```bat
run.bat --name Alice --port 9001 --peers 192.168.1.21:9002,192.168.1.22:9003,192.168.1.23:9004
```

The source repo also supports `run_demo.sh --peers ...` and
`run_demo.ps1 -Peers ...` to pass the same list to all four panes/windows.
If the access point blocks all client-to-client UDP, use a phone hotspot, a
switch, or run the four roles on one laptop.

## 4. Smart App Control blocks the Windows exe

Symptom: `check_demo.ps1` says the binary does not run, or Windows shows
`An Application Control policy has blocked this file`. The exe is unsigned.

Use the Linux bundle on a laptop, or a Windows machine where Smart App Control
is off. Do **not** turn off Smart App Control on a shared machine just for this
demo. The Windows CI runner executes the same code; the block is a local policy,
not a networking problem. The Linux bundle is the reliable fallback.

## 5. Duplicate names on the LAN

Two nodes with the same `--name` cannot both stay. meshchat resolves the
collision deterministically: the node with the larger public key prints a
`[fatal] duplicate peer name` error and exits; the other stays. If the instance
you wanted to keep exited, relaunch it with a different name:

```text
/quit
run.bat --name R2b --port 9004
```

Use the peer list's short fingerprint to tell instances apart. Names are display
labels, not identities.
