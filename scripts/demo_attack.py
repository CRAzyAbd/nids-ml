# scripts/demo_attack.py
"""
NIDS Attack Demo Script
=======================
Simulates realistic attack patterns on localhost so you can see
the NIDS dashboard fire alerts without needing a real attacker.

Simulates:
  1. Port Scan     — rapid connection attempts to many ports
  2. Brute Force   — repeated connection attempts to SSH port
  3. DoS pulse     — high-volume packet burst to a single port
  4. Normal traffic — DNS queries and HTTP requests (baseline)

Run WHILE the dashboard is running:
    # Terminal 1:
    sudo venv/bin/python3 main.py --mode dashboard

    # Terminal 2:
    python3 scripts/demo_attack.py

WARNING: Only run on your own machine / local network.
"""

import socket
import time
import threading
import random
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def color(text, code):
    return f"\033[{code}m{text}\033[0m"


def red(t):    return color(t, "91")
def green(t):  return color(t, "92")
def yellow(t): return color(t, "93")
def blue(t):   return color(t, "94")
def bold(t):   return color(t, "1")


def section(title, color_fn=bold):
    print(f"\n{color_fn('='*55)}")
    print(f"{color_fn(f'  {title}')}")
    print(f"{color_fn('='*55)}")


def simulate_port_scan(target="127.0.0.1", port_range=(20, 1024), delay=0.02):
    """
    Simulates a TCP SYN port scan.
    Connects rapidly to many ports — classic PortScan signature:
      - High SYN ratio
      - Very low bytes per flow
      - Very fast inter-arrival time
      - Many different destination ports
    """
    section("SIMULATING PORT SCAN", red)
    print(f"  Target : {target}")
    print(f"  Ports  : {port_range[0]} → {port_range[1]}")
    print(f"  Delay  : {delay}s between attempts\n")

    open_ports = []
    for port in range(port_range[0], port_range[1]):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.05)
            result = s.connect_ex((target, port))
            if result == 0:
                open_ports.append(port)
                print(f"  {green('OPEN')}  port {port}")
            s.close()
        except Exception:
            pass
        time.sleep(delay)

    print(f"\n  Scan complete. {len(open_ports)} open ports found: {open_ports}")


def simulate_brute_force(target="127.0.0.1", port=22, attempts=30, delay=0.1):
    """
    Simulates SSH brute force — repeated connection attempts to port 22.
    Signature: many flows to same dst_port, high RST ratio, uniform timing.
    """
    section("SIMULATING BRUTE FORCE (SSH)", yellow)
    print(f"  Target  : {target}:{port}")
    print(f"  Attempts: {attempts}")
    print(f"  Delay   : {delay}s\n")

    for i in range(attempts):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.2)
            s.connect_ex((target, port))
            # Send fake SSH client banner
            try:
                s.send(b"SSH-2.0-OpenSSH_8.0\r\n")
                s.recv(256)
            except Exception:
                pass
            s.close()
        except Exception:
            pass

        if (i + 1) % 10 == 0:
            print(f"  {yellow(f'Attempt {i+1}/{attempts}')} to {target}:{port}")
        time.sleep(delay)

    print(f"\n  Brute force complete — {attempts} attempts made")


def simulate_dos_pulse(target="127.0.0.1", port=80, duration=5, threads=10):
    """
    Simulates a DoS pulse — many connections in a short time.
    Signature: extreme bytes/sec, high packet count, very short duration.
    """
    section("SIMULATING DoS PULSE", red)
    print(f"  Target  : {target}:{port}")
    print(f"  Duration: {duration}s")
    print(f"  Threads : {threads}\n")

    stop_event = threading.Event()
    counts = [0]

    def worker():
        payload = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n" * 10
        while not stop_event.is_set():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.1)
                s.connect_ex((target, port))
                s.send(payload)
                s.close()
                counts[0] += 1
            except Exception:
                pass

    thread_list = []
    for _ in range(threads):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        thread_list.append(t)

    for i in range(duration):
        time.sleep(1)
        print(f"  {red(f'DoS pulse [{i+1}/{duration}s]')} — {counts[0]} connections so far")

    stop_event.set()
    print(f"\n  DoS complete — {counts[0]} total connections in {duration}s")


def simulate_normal_traffic(count=10):
    """
    Simulates normal DNS + HTTP traffic as a baseline.
    """
    section("SIMULATING NORMAL TRAFFIC", green)
    print(f"  Generating {count} normal requests...\n")

    domains = ["google.com", "github.com", "example.com",
               "cloudflare.com", "python.org"]

    for i in range(count):
        domain = random.choice(domains)
        try:
            # DNS lookup (UDP to port 53)
            socket.getaddrinfo(domain, 80)
            print(f"  {green('DNS')}   resolved {domain}")
        except Exception:
            pass
        time.sleep(random.uniform(0.2, 0.8))

    print(f"\n  Normal traffic complete")


def main():
    print(bold("\n" + "="*55))
    print(bold("  NIDS ATTACK DEMO SCRIPT"))
    print(bold("  Simulates attack patterns for dashboard testing"))
    print(bold("="*55))
    print(f"\n  {blue('Make sure the dashboard is running:')}")
    print(f"  sudo venv/bin/python3 main.py --mode dashboard")
    print(f"\n  {blue('Then open: http://localhost:5001')}")
    print(f"\n  Starting in 3 seconds...")
    time.sleep(3)

    # 1. Normal baseline first
    simulate_normal_traffic(count=5)
    time.sleep(2)

    # 2. Port scan
    simulate_port_scan(target="127.0.0.1", port_range=(20, 200), delay=0.02)
    time.sleep(3)

    # 3. Brute force
    simulate_brute_force(target="127.0.0.1", port=22, attempts=20, delay=0.15)
    time.sleep(3)

    # 4. DoS pulse
    simulate_dos_pulse(target="127.0.0.1", port=80, duration=4, threads=5)
    time.sleep(3)

    # 5. More normal traffic
    simulate_normal_traffic(count=5)

    print(bold("\n" + "="*55))
    print(bold("  DEMO COMPLETE"))
    print(bold("="*55))
    print(f"\n  Check your dashboard at {blue('http://localhost:5001')}")
    print(f"  You should see alerts in the feed and charts updated\n")


if __name__ == "__main__":
    main()
