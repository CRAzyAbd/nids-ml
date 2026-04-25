# src/sniffer/packet_capture.py
"""
Live packet capture module using Scapy.
Now integrated with FlowTracker for flow-level feature extraction.
"""

import csv
import os
from datetime import datetime
from collections import defaultdict

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

from config.settings import (
    INTERFACE, CAPTURE_FILTER, PACKET_COUNT,
    CAPTURED_DATA_DIR, STATS_INTERVAL, FLOWS_DATA_DIR,
)
from src.utils.logger import setup_logger
from src.features.flow_tracker import FlowTracker
from config.settings import LOG_FILE, LOG_LEVEL

logger = setup_logger(__name__, LOG_FILE, LOG_LEVEL)


class PacketCapture:
    """
    Captures live packets, extracts per-packet features,
    and feeds them into the FlowTracker for flow-level analysis.
    """

    def __init__(self, interface=INTERFACE, packet_filter=CAPTURE_FILTER,
                 packet_count=PACKET_COUNT):
        self.interface = interface
        self.packet_filter = packet_filter
        self.packet_count = packet_count
        self.packet_number = 0
        self.stats = defaultdict(int)

        # Per-packet CSV (same as Phase 1)
        os.makedirs(CAPTURED_DATA_DIR, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.packet_file = os.path.join(CAPTURED_DATA_DIR, f"packets_{timestamp}.csv")
        self._pkt_csv_file = open(self.packet_file, "w", newline="", encoding="utf-8")
        self._pkt_csv_writer = None

        # Flow-level CSV
        os.makedirs(FLOWS_DATA_DIR, exist_ok=True)
        self.flow_file = os.path.join(FLOWS_DATA_DIR, f"flows_{timestamp}.csv")
        self.flow_tracker = FlowTracker(session_file=self.flow_file)

        logger.info(f"PacketCapture initialized")
        logger.info(f"Interface    : {self.interface}")
        logger.info(f"Packet CSV   : {self.packet_file}")
        logger.info(f"Flow CSV     : {self.flow_file}")

    def _extract_features(self, packet) -> dict:
        """Extract per-packet features from a raw Scapy packet."""
        if not packet.haslayer(IP):
            return None

        ip_layer = packet[IP]

        features = {
            "timestamp":  datetime.now().isoformat(),
            "packet_num": self.packet_number,
            "src_ip":     ip_layer.src,
            "dst_ip":     ip_layer.dst,
            "ip_version": ip_layer.version,
            "ip_ttl":     ip_layer.ttl,
            "ip_proto":   ip_layer.proto,
            "packet_len": len(packet),
            "ip_flags":   str(ip_layer.flags),
            "src_port":   0,
            "dst_port":   0,
            "protocol":   "OTHER",
            "tcp_flags":  "",
            "tcp_seq":    0,
            "tcp_ack":    0,
            "tcp_window": 0,
            "payload_len": 0,
            "label":      "UNKNOWN",
        }

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            features.update({
                "protocol":   "TCP",
                "src_port":   tcp.sport,
                "dst_port":   tcp.dport,
                "tcp_seq":    tcp.seq,
                "tcp_ack":    tcp.ack,
                "tcp_window": tcp.window,
                "tcp_flags":  str(tcp.flags),
            })
            if packet.haslayer(Raw):
                features["payload_len"] = len(packet[Raw].load)

        elif packet.haslayer(UDP):
            udp = packet[UDP]
            features.update({
                "protocol": "UDP",
                "src_port": udp.sport,
                "dst_port": udp.dport,
            })
            if packet.haslayer(Raw):
                features["payload_len"] = len(packet[Raw].load)

        elif packet.haslayer(ICMP):
            features["protocol"] = "ICMP"

        return features

    def _process_packet(self, packet):
        """Callback: called by Scapy for every captured packet."""
        self.packet_number += 1
        features = self._extract_features(packet)

        if features is None:
            return

        # ── Write to per-packet CSV ───────────────────────────────
        if self._pkt_csv_writer is None:
            self._pkt_csv_writer = csv.DictWriter(
                self._pkt_csv_file, fieldnames=list(features.keys())
            )
            self._pkt_csv_writer.writeheader()
        self._pkt_csv_writer.writerow(features)
        self._pkt_csv_file.flush()

        # ── Feed into FlowTracker ─────────────────────────────────
        self.flow_tracker.process_packet(features)

        # ── Update protocol stats ─────────────────────────────────
        self.stats[features["protocol"]] += 1

        # ── Per-packet display ────────────────────────────────────
        self._display_packet(features)

        # ── Periodic stats ────────────────────────────────────────
        if self.packet_number % STATS_INTERVAL == 0:
            self._print_stats()

    def _display_packet(self, features: dict):
        """Print one line per packet to terminal."""
        proto = features["protocol"]
        colors = {"TCP": "\033[94m", "UDP": "\033[92m",
                  "ICMP": "\033[93m", "OTHER": "\033[90m"}
        reset = "\033[0m"
        color = colors.get(proto, "\033[90m")

        port_info = (f":{features['src_port']} → :{features['dst_port']}"
                     if proto in ("TCP", "UDP") else "")
        flags_info = (f" [{features['tcp_flags']}]"
                      if proto == "TCP" and features["tcp_flags"] else "")

        active = self.flow_tracker.get_active_flow_count()

        logger.info(
            f"#{self.packet_number:<5} {color}{proto}{reset} "
            f"{features['src_ip']}{port_info} → {features['dst_ip']} "
            f"| {features['packet_len']}B{flags_info} "
            f"[flows: {active}]"
        )

    def _print_stats(self):
        """Print protocol breakdown every STATS_INTERVAL packets."""
        logger.info("─" * 65)
        logger.info(f"  Packet stats after #{self.packet_number} | "
                    f"Active flows: {self.flow_tracker.get_active_flow_count()} | "
                    f"Completed flows: {len(self.flow_tracker.completed_flows)}")
        for proto, count in sorted(self.stats.items(), key=lambda x: -x[1]):
            bar = "█" * (count * 25 // max(self.stats.values()))
            pct = count / self.packet_number * 100
            logger.info(f"    {proto:<8} {count:>5} pkts ({pct:5.1f}%) {bar}")
        logger.info("─" * 65)

    def start(self):
        """Begin live capture."""
        logger.info("=" * 65)
        logger.info("  NIDS — Network Intrusion Detection System")
        logger.info("  Phase 2: Packet Capture + Flow Feature Extraction")
        logger.info("=" * 65)
        logger.info(f"Listening on '{self.interface}' | Press Ctrl+C to stop\n")

        try:
            sniff(
                iface=self.interface,
                filter=self.packet_filter,
                prn=self._process_packet,
                count=self.packet_count,
                store=False,
            )
        except KeyboardInterrupt:
            logger.info("\nCapture stopped by user.")
        except PermissionError:
            logger.error("Permission denied — run with: sudo venv/bin/python3 main.py")
        except Exception as e:
            logger.error(f"Error during capture: {e}")
        finally:
            self._pkt_csv_file.close()
            self.flow_tracker.export_all()
            self._print_stats()
            logger.info(f"\nPacket CSV : {self.packet_file}")
            logger.info(f"Flow CSV   : {self.flow_file}")
