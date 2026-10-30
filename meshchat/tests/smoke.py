#!/usr/bin/env python3
"""Real-process LAN smoke test for meshchat.

Starts six instances on one host over real UDP broadcast on :9999 and verifies:
  * every instance discovers every other instance
  * direct sealed messaging
  * a two-relay onion route, relay hex forwarding and relay blindness
  * removal of a killed peer and a subsequent onion delivery

Usage: python3 smoke.py /path/to/meshchat
"""

import os
import re
import subprocess
import sys
import threading
import time

NAMES = ["Alice", "Bob", "R1", "R2", "R3", "R4"]
PORTS = [19101, 19102, 19103, 19104, 19105, 19106]
REQUESTED_RELAYS = 2


class Proc:
    def __init__(self, binary, name, port):
        self.name = name
        self.buf = ""
        self.lock = threading.Lock()
        self.p = subprocess.Popen(
            [binary, "--name", name, "--port", str(port), "--no-color"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self):
        while True:
            line = self.p.stdout.readline()
            if not line:
                return
            with self.lock:
                self.buf += line

    def send(self, line):
        self.p.stdin.write(line + "\n")
        self.p.stdin.flush()

    def text(self):
        with self.lock:
            return self.buf

    def wait_for(self, needle, timeout=10.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if needle in self.text():
                return True
            if self.p.poll() is not None:
                return False
            time.sleep(0.05)
        return needle in self.text()

    def wait_for_new(self, needle, start, timeout=10.0):
        return self.wait_for(needle, timeout) and needle in self.text()[start:]

    def wait_line(self, predicate, timeout=15.0, start=0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            lines = self.text()[start:].splitlines()
            for line in reversed(lines):
                if predicate(line):
                    return line
            time.sleep(0.05)
        return None

    def quit(self):
        try:
            self.send("quit")
            self.p.wait(timeout=5)
        except Exception:
            try:
                self.p.kill()
            except Exception:
                pass


def latest_online(text):
    for line in reversed(text.splitlines()):
        if line.startswith("Online:"):
            return line
    return ""


def main():
    if len(sys.argv) < 2:
        print("usage: smoke.py <meshchat-binary>")
        return 2
    binary = os.path.abspath(sys.argv[1])
    if not os.path.exists(binary):
        print("binary not found:", binary)
        return 2

    procs = {}
    try:
        for name, port in zip(NAMES, PORTS):
            procs[name] = Proc(binary, name, port)
        for name, proc in procs.items():
            if not proc.wait_for("unicast UDP", 15):
                print("{} did not start:\n{}".format(name, proc.text()[-3000:]))
                return 1
        print("six instances started")

        # Each instance must see all five others through broadcast HELLO.
        deadline = time.time() + 15
        while time.time() < deadline:
            discovered_all = True
            for name, proc in procs.items():
                line = latest_online(proc.text())
                if not line or any(other not in line for other in NAMES if other != name):
                    discovered_all = False
                    break
            if discovered_all:
                break
            time.sleep(0.2)
        for name, proc in procs.items():
            line = latest_online(proc.text())
            if not line or any(other not in line for other in NAMES if other != name):
                print("{} did not discover everyone; latest list: {}".format(name, line))
                print(proc.text()[-4000:])
                return 1
        print("full peer discovery: OK")

        # Direct sealed message.
        alice, bob = procs["Alice"], procs["Bob"]
        alice.send("send Bob direct-hi")
        if not bob.wait_for("[Bob] Alice: direct-hi", 8):
            print("direct message was not received:\n" + bob.text()[-3000:])
            return 1
        print("direct sealed message: OK")

        # Two-relay onion message.
        alice_route_start = len(alice.text())
        alice.send("send Bob onion-hi --relays {} --verbose-route".format(REQUESTED_RELAYS))
        if not bob.wait_for("Alice: onion-hi", 10):
            print("onion message was not received:\n" + bob.text()[-4000:])
            print("alice:\n" + alice.text()[-2000:])
            return 1
        route_line = alice.wait_line(lambda line: line.startswith("[route] Alice ->"), 10,
                                     start=alice_route_start)
        if not route_line:
            print("no verbose route was printed:\n" + alice.text()[-3000:])
            return 1
        route = route_line.split("[route]", 1)[1].strip()
        parts = [part.strip() for part in route.split("->")]
        print("route:", " -> ".join(parts))
        if len(parts) != REQUESTED_RELAYS + 2 or parts[0] != "Alice" or parts[-1] != "Bob":
            print("unexpected route:", route_line)
            return 1
        relays = parts[1:-1]
        for relay in relays:
            if not procs[relay].wait_for("[RELAY] received", 8):
                print("{} did not print a relay line:\n{}".format(relay, procs[relay].text()[-3000:]))
                return 1

        # Relays only show ciphertext/hex, never the plaintext message.
        for name, proc in procs.items():
            if name == "Bob":
                continue
            if "onion-hi" in proc.text():
                print("plaintext leaked into {}'s output".format(name))
                return 1
        for relay in relays:
            if not re.search(r"\[RELAY\].*forwarded [0-9a-fA-F]{40,}", procs[relay].text()):
                print("{} relay line has no forwarded hex".format(relay))
                return 1
        print("two-relay onion + relay blindness: OK")

        # Kill R1 (clean quit -> BYE) and wait for its removal from Alice's list.
        r1 = procs["R1"]
        alice_list_start = len(alice.text())
        r1.quit()
        removed = alice.wait_line(
            lambda line: line.startswith("Online:")
            and "R1" not in line
            and all(other in line for other in ["Bob", "R2", "R3", "R4"]),
            15,
            start=alice_list_start,
        )
        if not removed:
            print("R1 was not removed from the peer list:\n" + alice.text()[-3000:])
            return 1
        print("dead peer removed:", removed)

        # A new onion send must adapt to the remaining relay pool.
        bob_start = len(bob.text())
        alice_route2_start = len(alice.text())
        alice.send("send Bob after-kill --relays {} --verbose-route".format(REQUESTED_RELAYS))
        if not bob.wait_for("Alice: after-kill", 10) or "Alice: after-kill" not in bob.text()[bob_start:]:
            print("post-kill onion message was not received:\n" + bob.text()[-3000:])
            print("alice:\n" + alice.text()[-2000:])
            return 1
        route2 = alice.wait_line(lambda line: line.startswith("[route] Alice ->"), 10,
                                 start=alice_route2_start)
        if route2:
            print("post-kill route:", route2.split("[route]", 1)[1].strip())
            if "-> R1" in route2:
                print("dead R1 was still selected")
                return 1
        for name, proc in procs.items():
            if name == "Bob":
                continue
            if "after-kill" in proc.text():
                print("plaintext leaked into {}'s output".format(name))
                return 1
        print("post-kill onion delivery: OK")

        print("MESHCHAT SMOKE OK")
        return 0
    finally:
        for proc in procs.values():
            proc.quit()
        for name, proc in procs.items():
            if proc.p.poll() is None:
                proc.p.kill()


if __name__ == "__main__":
    sys.exit(main())
