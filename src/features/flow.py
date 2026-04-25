# src/features/flow.py
"""
Represents a single network flow — one conversation between two endpoints.

A flow is defined by the 5-tuple:
    (src_ip, src_port, dst_ip, dst_port, protocol)

Packets arrive in two directions:
    FORWARD  — same direction as the first packet (initiator → responder)
    BACKWARD — opposite direction (responder → initiator)

We accumulate raw data here; FeatureExtractor will compute
statistics from it later.
"""

import time
from dataclasses import dataclass, field
from typing import List, Tuple


@dataclass
class Flow:
    """
    A single network flow (5-tuple conversation).

    dataclass automatically generates __init__, __repr__, etc.
    The `field(default_factory=list)` means each instance gets
    its own fresh list — NOT a shared list across all instances.
    """

    # ── Identity ─────────────────────────────────────────────────
    src_ip:   str
    src_port: int
    dst_ip:   str
    dst_port: int
    protocol: str

    # ── Timing ───────────────────────────────────────────────────
    start_time:   float = field(default_factory=time.time)
    last_seen:    float = field(default_factory=time.time)

    # ── Packet Storage ───────────────────────────────────────────
    # fwd = forward (same direction as first packet)
    # bwd = backward (reverse direction)
    fwd_packets: List[dict] = field(default_factory=list)
    bwd_packets: List[dict] = field(default_factory=list)

    # Inter-Arrival Times for each direction
    # IAT = time gap between consecutive packets in the same flow
    fwd_iats: List[float] = field(default_factory=list)  # seconds
    bwd_iats: List[float] = field(default_factory=list)

    # Timestamps of each packet (used to compute IAT)
    fwd_timestamps: List[float] = field(default_factory=list)
    bwd_timestamps: List[float] = field(default_factory=list)

    # TCP flag accumulators
    # We count how many times each flag appeared across all packets in this flow
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    urg_count: int = 0

    @property
    def flow_id(self) -> Tuple:
        """Unique identifier for this flow as a tuple."""
        return (self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.protocol)

    @property
    def total_packets(self) -> int:
        return len(self.fwd_packets) + len(self.bwd_packets)

    @property
    def total_fwd_bytes(self) -> int:
        """Sum of all forward packet lengths."""
        return sum(p["packet_len"] for p in self.fwd_packets)

    @property
    def total_bwd_bytes(self) -> int:
        """Sum of all backward packet lengths."""
        return sum(p["packet_len"] for p in self.bwd_packets)

    @property
    def duration(self) -> float:
        """Flow duration in seconds."""
        return max(self.last_seen - self.start_time, 1e-9)  # avoid division by zero

    def add_packet(self, packet_features: dict, is_forward: bool):
        """
        Add a packet to this flow.

        Args:
            packet_features: Dict from PacketCapture._extract_features()
            is_forward:      True if packet goes src→dst (same as flow init direction)
        """
        now = time.time()
        self.last_seen = now

        # Parse TCP flags from the string Scapy gives us (e.g., "SA", "S", "FA")
        flags_str = packet_features.get("tcp_flags", "")
        self._count_flags(flags_str)

        if is_forward:
            # Compute inter-arrival time (gap since last forward packet)
            if self.fwd_timestamps:
                iat = now - self.fwd_timestamps[-1]
                self.fwd_iats.append(iat)
            self.fwd_timestamps.append(now)
            self.fwd_packets.append(packet_features)
        else:
            if self.bwd_timestamps:
                iat = now - self.bwd_timestamps[-1]
                self.bwd_iats.append(iat)
            self.bwd_timestamps.append(now)
            self.bwd_packets.append(packet_features)

    def _count_flags(self, flags_str: str):
        """
        Parse a Scapy TCP flags string and increment our counters.

        Scapy represents TCP flags as a string of letters:
            "S"   = SYN
            "SA"  = SYN-ACK
            "A"   = ACK
            "FA"  = FIN-ACK
            "R"   = RST
            "PA"  = PSH-ACK (data push)
            "UA"  = URG-ACK

        We check for each letter individually.
        """
        if not flags_str:
            return
        # flags_str might look like "SA" or "<Flag 2 (SYN)>" depending on Scapy version
        # Convert to uppercase for safety
        f = flags_str.upper()
        if "S" in f: self.syn_count += 1
        if "A" in f: self.ack_count += 1
        if "F" in f: self.fin_count += 1
        if "R" in f: self.rst_count += 1
        if "P" in f: self.psh_count += 1
        if "U" in f: self.urg_count += 1

    def is_expired(self, timeout: float) -> bool:
        """Return True if this flow has been idle longer than timeout seconds."""
        return (time.time() - self.last_seen) > timeout

    def __repr__(self):
        return (
            f"Flow({self.src_ip}:{self.src_port} → {self.dst_ip}:{self.dst_port} "
            f"| {self.protocol} | {self.total_packets} pkts | {self.duration:.2f}s)"
        )
