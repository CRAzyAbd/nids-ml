# src/features/flow_tracker.py
"""
Manages all active flows across a capture session.

Responsibilities:
  1. Receive packets from PacketCapture one by one
  2. Route each packet to its correct Flow object
     (creating a new Flow if needed)
  3. Detect when flows expire (no new packets for FLOW_TIMEOUT seconds)
  4. Compute features on completed/expired flows
  5. Export feature rows to CSV

The key insight: We must handle BIDIRECTIONAL flows.
When we see a packet from 192.168.1.5:54231 → 8.8.8.8:53,
and then a reply from 8.8.8.8:53 → 192.168.1.5:54231,
these belong to the SAME flow, just different directions.
"""

import csv
import os
import time
from typing import Dict, Optional, Tuple

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
    """
    Tracks all active flows and manages their lifecycle.

    Attributes:
        flows:              Dict mapping flow_key → Flow object
        completed_flows:    List of extracted feature dicts (ready for ML)
        total_flows_seen:   Running count of all flows ever created
        _csv_writer:        Writes completed flow features to CSV
    """

    def __init__(self, session_file: str):
        """
        Args:
            session_file: Path for the flow features CSV output file
        """
        self.flows: Dict[Tuple, Flow] = {}   # active flows
        self.completed_flows = []             # exported feature dicts
        self.total_flows_seen = 0
        self._last_cleanup = time.time()

        # Set up CSV output
        os.makedirs(FLOWS_DATA_DIR, exist_ok=True)
        self.session_file = session_file
        self._csv_file = open(session_file, "w", newline="", encoding="utf-8")
        self._csv_writer = None   # initialized on first completed flow
        self._fieldnames = None

        logger.info(f"FlowTracker initialized → {session_file}")

    def _make_flow_key(self, features: dict) -> Tuple[Tuple, bool]:
        """
        Given a packet's features, find or create its flow key.

        Returns:
            (flow_key, is_forward)

            flow_key:   The canonical key to look up in self.flows
            is_forward: True if this packet goes in the "original" direction

        The canonical key always puts src first, so both directions
        of a conversation map to the same key.
        """
        src_ip   = features["src_ip"]
        dst_ip   = features["dst_ip"]
        src_port = features["src_port"]
        dst_port = features["dst_port"]
        protocol = features["protocol"]

        # Build the forward and backward keys
        fwd_key = (src_ip, src_port, dst_ip, dst_port, protocol)
        bwd_key = (dst_ip, dst_port, src_ip, src_port, protocol)

        # Check if either direction already exists
        if fwd_key in self.flows:
            return fwd_key, True
        elif bwd_key in self.flows:
            return bwd_key, False
        else:
            # New flow — use fwd_key as the canonical key
            return fwd_key, True

    def process_packet(self, features: dict):
        """
        Main entry point — called for every packet captured.

        Args:
            features: Packet feature dict from PacketCapture._extract_features()
        """
        if features is None:
            return

        # Periodically expire idle flows
        self._cleanup_expired_flows()

        # Find which flow this packet belongs to
        flow_key, is_forward = self._make_flow_key(features)

        # Create a new flow if this is the first packet of a conversation
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

        # Add this packet to the appropriate flow
        self.flows[flow_key].add_packet(features, is_forward)

        # Check if TCP flow is "complete" (FIN or RST flag seen)
        if self._is_tcp_terminated(features):
            self._export_flow(flow_key)

    def _is_tcp_terminated(self, features: dict) -> bool:
        """
        A TCP flow is considered complete when we see a FIN or RST flag.
        FIN = graceful close, RST = abrupt close.
        We can export and clean it up immediately.
        """
        flags = features.get("tcp_flags", "")
        return features["protocol"] == "TCP" and ("F" in flags or "R" in flags)

    def _cleanup_expired_flows(self):
        """
        Every 10 seconds, scan all active flows and expire idle ones.
        "Idle" means no packet received in FLOW_TIMEOUT seconds.
        """
        now = time.time()
        if now - self._last_cleanup < 10:
            return   # don't check every single packet — too slow
        self._last_cleanup = now

        expired_keys = [
            key for key, flow in self.flows.items()
            if flow.is_expired(FLOW_TIMEOUT)
        ]

        for key in expired_keys:
            self._export_flow(key)

        if expired_keys:
            logger.debug(f"Expired {len(expired_keys)} idle flows")

    def _export_flow(self, flow_key: Tuple):
        """
        Compute features for a flow and write them to CSV.
        Then remove the flow from active tracking.
        """
        flow = self.flows.pop(flow_key, None)
        if flow is None:
            return

        # Skip flows with too few packets — not enough data for statistics
        if flow.total_packets < MIN_PACKETS_PER_FLOW:
            return

        # Compute all statistical features
        feature_row = extract_features(flow)
        if feature_row is None:
            return

        self.completed_flows.append(feature_row)

        # Initialize CSV writer on first completed flow
        # (Now we know all the column names)
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

        # Periodically log a flow summary to the terminal
        if len(self.completed_flows) % FLOW_DISPLAY_INTERVAL == 0:
            self._display_flow_summary(feature_row)

    def _display_flow_summary(self, features: dict):
        """
        Print a human-readable summary of a completed flow.
        """
        proto = features["flow_protocol"]
        duration = features["duration"]
        total_pkts = features["total_packets"]
        total_bytes = features["total_bytes"]
        bps = features["bytes_per_sec"]
        syn_r = features["syn_ratio"]
        dst_cat = features.get("dst_port_category", "?")

        logger.info(
            f"  ✓ FLOW #{len(self.completed_flows):>5} | "
            f"{proto:<4} "
            f"{features['flow_src_ip']:>15}:{features['flow_src_port']:<5} → "
            f"{features['flow_dst_ip']:>15}:{features['flow_dst_port']:<5} "
            f"[{dst_cat}] | "
            f"{total_pkts:>4} pkts | "
            f"{total_bytes:>7} B | "
            f"{bps:>8.0f} B/s | "
            f"{duration:>6.2f}s | "
            f"SYN={syn_r:.2f}"
        )

    def export_all(self):
        """
        Called at end of capture — export every remaining active flow.
        """
        remaining = list(self.flows.keys())
        for key in remaining:
            self._export_flow(key)

        self._csv_file.close()
        logger.info(f"\n{'='*60}")
        logger.info(f"  FLOW SUMMARY")
        logger.info(f"  Total flows tracked: {self.total_flows_seen}")
        logger.info(f"  Flows exported:      {len(self.completed_flows)}")
        logger.info(f"  Output file:         {self.session_file}")
        logger.info(f"{'='*60}")

    def get_completed_flows(self) -> list:
        return self.completed_flows

    def get_active_flow_count(self) -> int:
        return len(self.flows)
