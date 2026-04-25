# src/sniffer/packet_capture.py
"""
Live packet capture module using Scapy.

How Scapy works at a high level:
  - Scapy talks directly to your OS's raw socket interface
  - It reads packets BEFORE they reach applications
  - Each "packet" is a layered structure: Ethernet → IP → TCP/UDP → Payload
  - We parse each layer to extract features

Requires root/sudo to capture packets (raw socket access is privileged).
"""

import csv
import os
from datetime import datetime
from collections import defaultdict

from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether, ARP, DNS, Raw
from scapy.layers.http import HTTPRequest, HTTPResponse

from config.settings import (
    INTERFACE,
    CAPTURE_FILTER,
    PACKET_COUNT,
    CAPTURED_DATA_DIR,
    STATS_INTERVAL,
)
from src.utils.logger import setup_logger
from config.settings import LOG_FILE, LOG_LEVEL

# Set up logger for this module
logger = setup_logger(__name__, LOG_FILE, LOG_LEVEL)


class PacketCapture:
    """
    Captures live network packets and extracts basic features.

    Attributes:
        interface:       Network interface to listen on (e.g., "ens33")
        packet_filter:   BPF filter string (e.g., "tcp", "port 80")
        packet_count:    Max packets to capture (0 = infinite)
        captured:        List of parsed packet dictionaries
        stats:           Protocol frequency counters
        session_file:    Path to CSV where we save this session's data
    """

    def __init__(self, interface=INTERFACE, packet_filter=CAPTURE_FILTER,
                 packet_count=PACKET_COUNT):
        self.interface = interface
        self.packet_filter = packet_filter
        self.packet_count = packet_count

        self.captured = []          # List of packet feature dicts
        self.packet_number = 0      # Running count of packets seen

        # Protocol counters — defaultdict(int) means missing keys default to 0
        self.stats = defaultdict(int)

        # Create a timestamped CSV file for this capture session
        os.makedirs(CAPTURED_DATA_DIR, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.session_file = os.path.join(CAPTURED_DATA_DIR, f"capture_{timestamp}.csv")

        # CSV writer — we open the file once and write to it continuously
        self._csv_file = open(self.session_file, "w", newline="", encoding="utf-8")
        self._csv_writer = None  # We'll initialize this on first packet

        logger.info(f"PacketCapture initialized")
        logger.info(f"Interface   : {self.interface}")
        logger.info(f"Filter      : '{self.packet_filter}' (empty = capture all)")
        logger.info(f"Output file : {self.session_file}")

    def _extract_features(self, packet) -> dict:
        """
        Parse a raw Scapy packet and extract a flat dictionary of features.

        A Scapy packet is organized in layers. To check if a layer exists:
            packet.haslayer(TCP)  → True/False
        To access a layer:
            packet[IP].src        → source IP string

        Returns a dict with one value per feature, or None if the packet
        has no IP layer (e.g., ARP packets — we skip those for now).
        """

        # We only process IP packets in this phase
        # (ARP, spanning tree, etc. are skipped)
        if not packet.haslayer(IP):
            return None

        ip_layer = packet[IP]

        # ── Basic IP Features ────────────────────────────────────
        features = {
            "timestamp":    datetime.now().isoformat(),
            "packet_num":   self.packet_number,

            # IP layer fields
            "src_ip":       ip_layer.src,         # Source IP address
            "dst_ip":       ip_layer.dst,         # Destination IP address
            "ip_version":   ip_layer.version,     # 4 or 6
            "ip_ttl":       ip_layer.ttl,         # Time-to-live (hops remaining)
            "ip_proto":     ip_layer.proto,       # Protocol number (6=TCP, 17=UDP, 1=ICMP)
            "packet_len":   len(packet),          # Total packet size in bytes
            "ip_flags":     str(ip_layer.flags),  # DF (Don't Fragment), MF (More Fragments)

            # Ports (default 0 for non-TCP/UDP)
            "src_port":     0,
            "dst_port":     0,

            # Protocol name (human-readable)
            "protocol":     "OTHER",

            # TCP-specific flags (default 0)
            "tcp_flags":    "",
            "tcp_seq":      0,
            "tcp_ack":      0,
            "tcp_window":   0,

            # Payload size
            "payload_len":  0,

            # Labels (for Phase 4 — we'll fill these in during training)
            "label":        "UNKNOWN",
        }

        # ── TCP Layer ────────────────────────────────────────────
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            features["protocol"]    = "TCP"
            features["src_port"]    = tcp.sport      # Source port
            features["dst_port"]    = tcp.dport      # Destination port
            features["tcp_seq"]     = tcp.seq        # Sequence number
            features["tcp_ack"]     = tcp.ack        # Acknowledgment number
            features["tcp_window"]  = tcp.window     # Window size (flow control)
            features["tcp_flags"]   = str(tcp.flags) # SYN, ACK, FIN, RST, PSH, URG

            # Payload = the actual data inside TCP
            if packet.haslayer(Raw):
                features["payload_len"] = len(packet[Raw].load)

        # ── UDP Layer ────────────────────────────────────────────
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            features["protocol"]  = "UDP"
            features["src_port"]  = udp.sport
            features["dst_port"]  = udp.dport

            if packet.haslayer(Raw):
                features["payload_len"] = len(packet[Raw].load)

        # ── ICMP Layer ───────────────────────────────────────────
        elif packet.haslayer(ICMP):
            features["protocol"] = "ICMP"

        return features

    def _initialize_csv_writer(self, fieldnames: list):
        """
        Write the CSV header row on the first packet.
        We don't know fieldnames until we parse the first packet.
        """
        self._csv_writer = csv.DictWriter(self._csv_file, fieldnames=fieldnames)
        self._csv_writer.writeheader()
        self._csv_file.flush()

    def _process_packet(self, packet):
        """
        Callback function — Scapy calls this for EVERY captured packet.
        This is where we extract features, display them, and save them.
        """
        self.packet_number += 1

        # Extract features from this packet
        features = self._extract_features(packet)

        # Skip non-IP packets
        if features is None:
            return

        # ── Initialize CSV on first packet ───────────────────────
        if self._csv_writer is None:
            self._initialize_csv_writer(list(features.keys()))

        # Save to our in-memory list
        self.captured.append(features)

        # Write to CSV immediately (flush ensures data is written even if we Ctrl+C)
        self._csv_writer.writerow(features)
        self._csv_file.flush()

        # ── Update Protocol Stats ─────────────────────────────────
        self.stats[features["protocol"]] += 1

        # ── Terminal Display ──────────────────────────────────────
        self._display_packet(features)

        # ── Periodic Stats Summary ────────────────────────────────
        if self.packet_number % STATS_INTERVAL == 0:
            self._print_stats()

    def _display_packet(self, features: dict):
        """
        Print a single packet's key info to the terminal.
        """
        proto = features["protocol"]

        # Color-code by protocol for readability
        if proto == "TCP":
            proto_display = f"\033[94mTCP\033[0m"     # Blue
        elif proto == "UDP":
            proto_display = f"\033[92mUDP\033[0m"     # Green
        elif proto == "ICMP":
            proto_display = f"\033[93mICMP\033[0m"    # Yellow
        else:
            proto_display = f"\033[90mOTHER\033[0m"   # Gray

        # Format port display (only meaningful for TCP/UDP)
        if proto in ("TCP", "UDP"):
            port_info = f":{features['src_port']} → :{features['dst_port']}"
        else:
            port_info = ""

        # Build flags display for TCP
        flags_info = ""
        if proto == "TCP" and features["tcp_flags"]:
            flags_info = f" [{features['tcp_flags']}]"

        logger.info(
            f"#{self.packet_number:<5} {proto_display} "
            f"{features['src_ip']}{port_info} → {features['dst_ip']} "
            f"| {features['packet_len']} bytes"
            f"{flags_info}"
        )

    def _print_stats(self):
        """
        Print a summary of protocols seen so far.
        """
        logger.info("─" * 60)
        logger.info(f"  STATS after {self.packet_number} packets:")
        for proto, count in sorted(self.stats.items(), key=lambda x: -x[1]):
            bar = "█" * (count * 30 // max(self.stats.values()))
            pct = count / self.packet_number * 100
            logger.info(f"    {proto:<8} {count:>5} packets ({pct:5.1f}%) {bar}")
        logger.info("─" * 60)

    def start(self):
        """
        Begin capturing packets. Blocks until PACKET_COUNT reached or Ctrl+C.
        """
        logger.info("=" * 60)
        logger.info("  NIDS — Network Intrusion Detection System")
        logger.info("  Phase 1: Packet Capture")
        logger.info("=" * 60)
        logger.info(f"Starting capture on interface '{self.interface}'...")
        logger.info("Press Ctrl+C to stop.\n")

        try:
            # scapy's sniff() is the core capture function:
            #   iface   = which network interface to listen on
            #   filter  = BPF filter (e.g., "tcp", "port 80", "host 192.168.1.1")
            #   prn     = callback function called for each packet
            #   count   = how many packets (0 = forever)
            #   store   = False means don't store packets in RAM (we handle storage ourselves)
            sniff(
                iface=self.interface,
                filter=self.packet_filter,
                prn=self._process_packet,
                count=self.packet_count,
                store=False,
            )

        except KeyboardInterrupt:
            logger.info("\nCapture stopped by user (Ctrl+C).")

        except PermissionError:
            logger.error("Permission denied! Raw socket access requires root.")
            logger.error("Run with: sudo python3 main.py")

        except Exception as e:
            logger.error(f"Unexpected error during capture: {e}")

        finally:
            # Always close the CSV file cleanly
            self._csv_file.close()
            self._print_stats()
            logger.info(f"\nCapture saved to: {self.session_file}")
            logger.info(f"Total packets captured: {len(self.captured)}")

    def get_captured_data(self) -> list:
        """Return the list of captured packet feature dictionaries."""
        return self.captured

