# config/settings.py
"""
Central configuration for the NIDS project.
Change values here — never hardcode them in other files.
"""

import os

# ─── Project Root ────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ─── Network Interface ───────────────────────────────────────────
# Change this to YOUR interface name (find it with: ip link show)
INTERFACE = "wlo1"

CAPTURE_FILTER = ""      # BPF filter: "tcp", "port 80", "" = everything
PACKET_COUNT = 0         # 0 = capture forever

# ─── Flow Tracking ───────────────────────────────────────────────
# A "flow" is a conversation between two endpoints (5-tuple).
# We expire a flow if no packet has been seen for this many seconds.
FLOW_TIMEOUT = 120       # seconds — TCP connections usually timeout here

# After this many seconds, we force-export all active flows and clear them.
# This keeps memory bounded during long captures.
FLOW_EXPORT_INTERVAL = 60   # seconds

# Minimum packets a flow must have before we bother computing features.
# A flow with 1 packet has no statistics (no inter-arrival time, no std dev).
MIN_PACKETS_PER_FLOW = 2

# ─── Well-Known Ports ────────────────────────────────────────────
# We classify destination ports into service categories.
# This gives ML models a semantic signal instead of raw port numbers.
PORT_CATEGORIES = {
    "web":      {80, 443, 8080, 8443},
    "dns":      {53},
    "mail":     {25, 465, 587, 110, 995, 143, 993},
    "ftp":      {20, 21},
    "ssh":      {22},
    "telnet":   {23},
    "smb":      {445, 139},
    "rdp":      {3389},
    "database": {3306, 5432, 1433, 27017, 6379},
    "ntp":      {123},
}

# ─── Logging ─────────────────────────────────────────────────────
LOG_DIR = os.path.join(BASE_DIR, "logs")
LOG_FILE = os.path.join(LOG_DIR, "nids.log")
LOG_LEVEL = "INFO"

# ─── Output Directories ──────────────────────────────────────────
CAPTURED_DATA_DIR = os.path.join(BASE_DIR, "captured_data")
FLOWS_DATA_DIR    = os.path.join(BASE_DIR, "captured_data", "flows")

# ─── Display Settings ────────────────────────────────────────────
STATS_INTERVAL = 50   # Print packet stats every N packets
FLOW_DISPLAY_INTERVAL = 10  # Print completed flow summary every N flows
