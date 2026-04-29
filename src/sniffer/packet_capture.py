# src/sniffer/packet_capture.py
"""
Live packet capture — Phase 5 update.
Supports two modes:
  mode="capture" : Phase 1/2 behaviour — capture + save flows to CSV
  mode="detect"  : Phase 5 — capture + classify flows in real time
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
from config.settings import LOG_FILE, LOG_LEVEL

logger = setup_logger(__name__, LOG_FILE, LOG_LEVEL)


class PacketCapture:
    """
    Captures live packets and either saves flows (capture mode)
    or classifies them in real time (detect mode).
    """

    def __init__(self,
                 interface=INTERFACE,
                 packet_filter=CAPTURE_FILTER,
                 packet_count=PACKET_COUNT,
                 mode="capture",
                 detector=None,
                 alert_engine=None):
        """
        Args:
            interface:     Network interface to sniff on
            packet_filter: BPF filter string
            packet_count:  Max packets (0 = infinite)
            mode:          "capture" or "detect"
            detector:      RealTimeDetector instance (detect mode only)
            alert_engine:  AlertEngine instance (detect mode only)
        """
        self.interface     = interface
        self.packet_filter = packet_filter
        self.packet_count  = packet_count
        self.mode          = mode
        self.detector      = detector
        self.alert_engine  = alert_engine
        self.packet_number = 0
        self.stats         = defaultdict(int)

        # Set up flow tracker
        os.makedirs(FLOWS_DATA_DIR, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        flow_file = os.path.join(FLOWS_DATA_DIR, f"flows_{timestamp}.csv")

        # Import here to avoid circular imports
        from src.features.flow_tracker import FlowTracker

        if mode == "detect":
            # In detect mode, pass a callback to the flow tracker
            # so it calls our detector when a flow completes
            self.flow_tracker = FlowTracker(
                session_file=flow_file,
                on_flow_complete=self._on_flow_complete,
            )
        else:
            self.flow_tracker = FlowTracker(session_file=flow_file)

        # Per-packet CSV (capture mode only)
        if mode == "capture":
            os.makedirs(CAPTURED_DATA_DIR, exist_ok=True)
            pkt_file = os.path.join(CAPTURED_DATA_DIR, f"packets_{timestamp}.csv")
            self._pkt_csv_file   = open(pkt_file, "w", newline="", encoding="utf-8")
            self._pkt_csv_writer = None
        else:
            self._pkt_csv_file   = None
            self._pkt_csv_writer = None

        logger.info(f"PacketCapture initialized | mode={mode} | interface={interface}")

    def _on_flow_complete(self, flow_features: dict):
        """
        Callback invoked by FlowTracker when a flow is exported.
        In detect mode, we classify the flow and pass to AlertEngine.
        """
        if self.detector is None or self.alert_engine is None:
            return
        try:
            result = self.detector.classify(flow_features)
            self.alert_engine.process(result)
        except Exception as e:
            logger.error(f"Detection error: {e}")

    def _extract_features(self, packet) -> dict:
        """Extract per-packet features from a raw Scapy packet."""
        if not packet.haslayer(IP):
            return None

        ip = packet[IP]
        features = {
            "timestamp":   datetime.now().isoformat(),
            "packet_num":  self.packet_number,
            "src_ip":      ip.src,
            "dst_ip":      ip.dst,
            "ip_version":  ip.version,
            "ip_ttl":      ip.ttl,
            "ip_proto":    ip.proto,
            "packet_len":  len(packet),
            "ip_flags":    str(ip.flags),
            "src_port":    0,
            "dst_port":    0,
            "protocol":    "OTHER",
            "tcp_flags":   "",
            "tcp_seq":     0,
            "tcp_ack":     0,
            "tcp_window":  0,
            "payload_len": 0,
            "label":       "UNKNOWN",
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

        # Write per-packet CSV in capture mode
        if self.mode == "capture" and self._pkt_csv_file:
            if self._pkt_csv_writer is None:
                self._pkt_csv_writer = csv.DictWriter(
                    self._pkt_csv_file, fieldnames=list(features.keys())
                )
                self._pkt_csv_writer.writeheader()
            self._pkt_csv_writer.writerow(features)
            self._pkt_csv_file.flush()

        # Feed into FlowTracker (both modes)
        self.flow_tracker.process_packet(features)

        self.stats[features["protocol"]] += 1

        # Lightweight per-packet display
        if self.mode == "capture":
            self._display_packet(features)

        if self.packet_number % STATS_INTERVAL == 0:
            self._print_packet_stats()

    def _display_packet(self, features: dict):
        proto  = features["protocol"]
        colors = {
            "TCP": "\033[94m", "UDP": "\033[92m",
            "ICMP": "\033[93m", "OTHER": "\033[90m"
        }
        color = colors.get(proto, "\033[90m")
        reset = "\033[0m"
        port_info = (f":{features['src_port']} → :{features['dst_port']}"
                     if proto in ("TCP", "UDP") else "")
        active = self.flow_tracker.get_active_flow_count()
        logger.info(
            f"#{self.packet_number:<5} {color}{proto}{reset} "
            f"{features['src_ip']}{port_info} → {features['dst_ip']} "
            f"| {features['packet_len']}B [flows:{active}]"
        )

    def _print_packet_stats(self):
        logger.info("─" * 60)
        logger.info(f"  Packets: {self.packet_number} | "
                    f"Active flows: {self.flow_tracker.get_active_flow_count()}")
        for proto, count in sorted(self.stats.items(), key=lambda x: -x[1]):
            pct = count / self.packet_number * 100
            logger.info(f"    {proto:<8} {count:>5}  ({pct:.1f}%)")
        logger.info("─" * 60)

    def start(self):
        """Begin live capture."""
        mode_label = "Real-Time Detection" if self.mode == "detect" else "Packet Capture"
        logger.info("=" * 60)
        logger.info(f"  NIDS — {mode_label}")
        logger.info(f"  Interface : {self.interface}")
        logger.info(f"  Filter    : '{self.packet_filter}' (empty=all)")
        logger.info("  Press Ctrl+C to stop")
        logger.info("=" * 60 + "\n")

        try:
            sniff(
                iface=self.interface,
                filter=self.packet_filter,
                prn=self._process_packet,
                count=self.packet_count,
                store=False,
            )
        except KeyboardInterrupt:
            logger.info("\nCapture stopped.")
        except PermissionError:
            logger.error("Permission denied — run with: sudo venv/bin/python3 main.py")
        except Exception as e:
            logger.error(f"Capture error: {e}")
        finally:
            if self._pkt_csv_file:
                self._pkt_csv_file.close()
            self.flow_tracker.export_all()

            if self.mode == "detect" and self.alert_engine:
                self.alert_engine.print_final_summary()
