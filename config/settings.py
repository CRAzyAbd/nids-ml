# config/settings.py
"""
Central configuration for the NIDS project.
Change values here — never hardcode them in other files.
"""

import os

# ─── Project Root ────────────────────────────────────────────────
# os.path.dirname(__file__) gives us the config/ folder
# Going one level up gives us the project root
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ─── Network Interface ───────────────────────────────────────────
# Change this to your interface name (find it with: ip link show)
INTERFACE = "wlo1"   # ← CHANGE THIS to your interface

# Optional BPF filter string (Berkeley Packet Filter)
# Examples:
#   "tcp"         → only TCP packets
#   "port 80"     → only HTTP traffic
#   "not port 22" → exclude SSH (so you don't flood logs while working)
#   ""            → capture everything
CAPTURE_FILTER = ""

# How many packets to capture (0 = capture forever until Ctrl+C)
PACKET_COUNT = 0

# ─── Logging ─────────────────────────────────────────────────────
LOG_DIR = os.path.join(BASE_DIR, "logs")
LOG_FILE = os.path.join(LOG_DIR, "nids.log")
LOG_LEVEL = "INFO"  # Options: DEBUG, INFO, WARNING, ERROR, CRITICAL

# ─── Capture Output ──────────────────────────────────────────────
CAPTURED_DATA_DIR = os.path.join(BASE_DIR, "captured_data")

# ─── Display Settings ────────────────────────────────────────────
# How many packets to show in summary before printing stats
STATS_INTERVAL = 100  # Print statistics every N packets
