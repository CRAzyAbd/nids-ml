# src/features/flow_tracker.py
import csv
import os
import time
from typing import Dict, Tuple

from src.features.flow import Flow
from src.features.feature_extractor import extract_features
from src.utils.logger import setup_logger
from config.settings import (
    LOG_FILE, LOG_LEVEL,
    FLOW_TIMEOUT, MIN_PACKETS_PER_FLOW,
    FLOWS_DATA_DIR, FLOW_DISPLAY_INTERVAL,
)

logger = setup_logger(__name__, LOG_FILE, LOG_LEVEL)


class FlowTracker:

    def __init__(self, session_file: str, on_flow_complete=None):
        self.flows = {}
        self.completed_flows = []
        self.total_flows_seen = 0
        self._last_cleanup = time.time()
        self.on_flow_complete = on_flow_complete

        os.makedirs(FLOWS_DATA_DIR, exist_ok=True)
        self.session_file = session_file
        self._csv_file = open(session_file, "w", newline="", encoding="utf-8")
        self._csv_writer = None
        self._fieldnames = None

        logger.info(f"FlowTracker initialized -> {session_file}")

    def _make_flow_key(self, features: dict):
        src_ip   = features["src_ip"]
        dst_ip   = features["dst_ip"]
        src_port = features["src_port"]
        dst_port = features["dst_port"]
        protocol = features["protocol"]

        fwd_key = (src_ip, src_port, dst_ip, dst_port, protocol)
        bwd_key = (dst_ip, dst_port, src_ip, src_port, protocol)

        if fwd_key in self.flows:
            return fwd_key, True
        elif bwd_key in self.flows:
            return bwd_key, False
        else:
            return fwd_key, True

    def process_packet(self, features: dict):
        if features is None:
            return

        self._cleanup_expired_flows()

        flow_key, is_forward = self._make_flow_key(features)

        if flow_key not in self.flows:
            src_ip, src_port, dst_ip, dst_port, protocol = flow_key
            self.flows[flow_key] = Flow(
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=protocol,
            )
            self.total_flows_seen += 1

        self.flows[flow_key].add_packet(features, is_forward)

        if self._is_tcp_terminated(features):
            self._export_flow(flow_key)

    def _is_tcp_terminated(self, features: dict) -> bool:
        flags = features.get("tcp_flags", "")
        return features["protocol"] == "TCP" and ("F" in flags or "R" in flags)

    def _cleanup_expired_flows(self):
        now = time.time()
        if now - self._last_cleanup < 10:
            return
        self._last_cleanup = now

        expired_keys = [
            key for key, flow in self.flows.items()
            if flow.is_expired(FLOW_TIMEOUT)
        ]
        for key in expired_keys:
            self._export_flow(key)

    def _export_flow(self, flow_key):
        flow = self.flows.pop(flow_key, None)
        if flow is None:
            return

        if flow.total_packets < MIN_PACKETS_PER_FLOW:
            return

        feature_row = extract_features(flow)
        if feature_row is None:
            return

        self.completed_flows.append(feature_row)

        if self._csv_writer is None:
            self._fieldnames = list(feature_row.keys())
            self._csv_writer = csv.DictWriter(
                self._csv_file,
                fieldnames=self._fieldnames,
                extrasaction="ignore"
            )
            self._csv_writer.writeheader()

        self._csv_writer.writerow(feature_row)
        self._csv_file.flush()

        if self.on_flow_complete is not None:
            self.on_flow_complete(feature_row)

        if len(self.completed_flows) % FLOW_DISPLAY_INTERVAL == 0:
            self._display_flow_summary(feature_row)

    def _display_flow_summary(self, features: dict):
        proto      = features["flow_protocol"]
        total_pkts = features["total_packets"]
        total_bytes = features["total_bytes"]
        bps        = features["bytes_per_sec"]
        duration   = features["duration"]
        syn_r      = features["syn_ratio"]
        dst_cat    = features.get("dst_port_category", "?")

        logger.info(
            f"  FLOW #{len(self.completed_flows):>5} | "
            f"{proto:<4} "
            f"{features['flow_src_ip']:>15}:{features['flow_src_port']:<5} -> "
            f"{features['flow_dst_ip']:>15}:{features['flow_dst_port']:<5} "
            f"[{dst_cat}] | "
            f"{total_pkts:>4} pkts | "
            f"{total_bytes:>7} B | "
            f"{bps:>8.0f} B/s | "
            f"{duration:>6.2f}s | "
            f"SYN={syn_r:.2f}"
        )

    def export_all(self):
        remaining = list(self.flows.keys())
        for key in remaining:
            self._export_flow(key)

        self._csv_file.close()
        logger.info(f"FlowTracker: {self.total_flows_seen} flows total, "
                    f"{len(self.completed_flows)} exported -> {self.session_file}")

    def get_completed_flows(self) -> list:
        return self.completed_flows

    def get_active_flow_count(self) -> int:
        return len(self.flows)
