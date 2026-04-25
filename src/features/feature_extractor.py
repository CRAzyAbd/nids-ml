# src/features/feature_extractor.py
"""
Computes statistical features from a completed Flow object.

Every feature here is chosen because it helps distinguish
normal traffic from attack traffic:

- PORT SCANS:     many flows, all to different dst_ports, all SYN-only,
                  very fast IAT, very few packets per flow
- DoS ATTACKS:    enormous bytes/sec, huge packet count, single destination
- DATA EXFIL:     high fwd/bwd byte ratio (lots going OUT), large payloads
- NORMAL WEB:     moderate size, mix of SYN+ACK+PSH+FIN, consistent IAT

We produce a flat dict of numbers — no strings, no IPs.
That dict maps directly to a pandas DataFrame row.
"""

import numpy as np
from config.settings import PORT_CATEGORIES


def _safe_stat(values: list) -> dict:
    """
    Compute mean, std, max, min of a list of numbers.
    Returns zeros if the list is empty or has only one element.

    We use numpy for efficiency. np.std([x]) = 0.0 which is correct.
    """
    if not values:
        return {"mean": 0.0, "std": 0.0, "max": 0.0, "min": 0.0}
    arr = np.array(values, dtype=float)
    return {
        "mean": float(np.mean(arr)),
        "std":  float(np.std(arr)),
        "max":  float(np.max(arr)),
        "min":  float(np.min(arr)),
    }


def _classify_port(port: int) -> str:
    """
    Map a port number to a service category string.
    Returns "ephemeral" for ports ≥ 1024 that aren't in our known list,
    and "unknown" if port is 0 (non-TCP/UDP protocols).
    """
    if port == 0:
        return "unknown"
    for category, ports in PORT_CATEGORIES.items():
        if port in ports:
            return category
    if port < 1024:
        return "system"      # Reserved but not in our list
    return "ephemeral"       # Dynamic/private port range (1024-65535)


def extract_features(flow) -> dict:
    """
    Given a Flow object, return a flat dict of numerical features.

    This is the function that bridges raw network data → ML input.

    Args:
        flow: A Flow instance (from src/features/flow.py)

    Returns:
        A dict with all features as Python floats/ints.
        Returns None if the flow doesn't have enough data.
    """

    # ── Sanity check ─────────────────────────────────────────────
    if flow.total_packets < 2:
        return None   # Cannot compute statistics on a single packet

    # ── Packet length lists ───────────────────────────────────────
    fwd_lens = [p["packet_len"] for p in flow.fwd_packets]
    bwd_lens = [p["packet_len"] for p in flow.bwd_packets]
    all_lens = fwd_lens + bwd_lens

    fwd_payload_lens = [p["payload_len"] for p in flow.fwd_packets]
    bwd_payload_lens = [p["payload_len"] for p in flow.bwd_packets]

    # ── Statistics ────────────────────────────────────────────────
    fwd_len_stats  = _safe_stat(fwd_lens)
    bwd_len_stats  = _safe_stat(bwd_lens)
    all_len_stats  = _safe_stat(all_lens)
    fwd_iat_stats  = _safe_stat(flow.fwd_iats)
    bwd_iat_stats  = _safe_stat(flow.bwd_iats)

    # Overall flow IAT = IAT across all packets regardless of direction
    all_iats = flow.fwd_iats + flow.bwd_iats
    all_iat_stats  = _safe_stat(all_iats)

    # ── Derived Values ────────────────────────────────────────────
    total_bytes     = flow.total_fwd_bytes + flow.total_bwd_bytes
    duration        = flow.duration
    total_packets   = flow.total_packets

    bytes_per_sec   = total_bytes   / duration
    packets_per_sec = total_packets / duration

    # Byte ratio: what fraction of bytes went forward (away from initiator)?
    # A ratio close to 1.0 means nearly all bytes went one direction.
    # Exfiltration → high forward ratio (sending lots out)
    bwd_fwd_byte_ratio = (
        flow.total_bwd_bytes / flow.total_fwd_bytes
        if flow.total_fwd_bytes > 0 else 0.0
    )

    # Average payload (data content) per packet
    total_payload = sum(fwd_payload_lens) + sum(bwd_payload_lens)
    avg_payload   = total_payload / total_packets if total_packets > 0 else 0.0

    # ── Flag Ratios ───────────────────────────────────────────────
    # Ratios are more useful than raw counts because flows have different lengths.
    # A SYN ratio of 1.0 means EVERY packet was SYN — classic port scan signature.
    total_flag_denom = max(total_packets, 1)  # avoid division by zero
    syn_ratio = flow.syn_count / total_flag_denom
    ack_ratio = flow.ack_count / total_flag_denom
    fin_ratio = flow.fin_count / total_flag_denom
    rst_ratio = flow.rst_count / total_flag_denom
    psh_ratio = flow.psh_count / total_flag_denom
    urg_ratio = flow.urg_count / total_flag_denom

    # ── Port Classification ───────────────────────────────────────
    dst_port_cat = _classify_port(flow.dst_port)
    src_port_cat = _classify_port(flow.src_port)

    # One-hot encode port category for ML
    # (We can't feed a string "web" to sklearn — we need numbers)
    all_categories = list(PORT_CATEGORIES.keys()) + ["system", "ephemeral", "unknown"]
    dst_port_onehot = {
        f"dst_port_{cat}": int(dst_port_cat == cat)
        for cat in all_categories
    }

    # ── Build Feature Dict ────────────────────────────────────────
    features = {
        # ── Flow Identity (for debugging — not fed to ML) ─────────
        "flow_src_ip":   flow.src_ip,
        "flow_dst_ip":   flow.dst_ip,
        "flow_src_port": flow.src_port,
        "flow_dst_port": flow.dst_port,
        "flow_protocol": flow.protocol,

        # ── Timing ───────────────────────────────────────────────
        "duration":         duration,
        "flow_start_time":  flow.start_time,

        # ── Volume ───────────────────────────────────────────────
        "total_fwd_packets":  len(flow.fwd_packets),
        "total_bwd_packets":  len(flow.bwd_packets),
        "total_fwd_bytes":    flow.total_fwd_bytes,
        "total_bwd_bytes":    flow.total_bwd_bytes,
        "total_bytes":        total_bytes,
        "total_packets":      total_packets,

        # ── Rates ────────────────────────────────────────────────
        "bytes_per_sec":    bytes_per_sec,
        "pkts_per_sec":     packets_per_sec,

        # ── Packet Length Statistics ──────────────────────────────
        "fwd_pkt_len_mean": fwd_len_stats["mean"],
        "fwd_pkt_len_std":  fwd_len_stats["std"],
        "fwd_pkt_len_max":  fwd_len_stats["max"],
        "fwd_pkt_len_min":  fwd_len_stats["min"],

        "bwd_pkt_len_mean": bwd_len_stats["mean"],
        "bwd_pkt_len_std":  bwd_len_stats["std"],
        "bwd_pkt_len_max":  bwd_len_stats["max"],
        "bwd_pkt_len_min":  bwd_len_stats["min"],

        "avg_pkt_len":      all_len_stats["mean"],
        "std_pkt_len":      all_len_stats["std"],

        # ── Inter-Arrival Time Statistics (seconds) ───────────────
        # IAT measures the REGULARITY of packet timing.
        # Very low IAT + very low std = automated/scripted traffic (scans, bots).
        "fwd_iat_mean":     fwd_iat_stats["mean"],
        "fwd_iat_std":      fwd_iat_stats["std"],
        "fwd_iat_max":      fwd_iat_stats["max"],
        "fwd_iat_min":      fwd_iat_stats["min"],

        "bwd_iat_mean":     bwd_iat_stats["mean"],
        "bwd_iat_std":      bwd_iat_stats["std"],
        "bwd_iat_max":      bwd_iat_stats["max"],
        "bwd_iat_min":      bwd_iat_stats["min"],

        "flow_iat_mean":    all_iat_stats["mean"],
        "flow_iat_std":     all_iat_stats["std"],

        # ── Byte Ratios ───────────────────────────────────────────
        "bwd_fwd_byte_ratio": bwd_fwd_byte_ratio,
        "avg_payload_len":    avg_payload,

        # ── TCP Flags (raw counts) ────────────────────────────────
        "syn_count": flow.syn_count,
        "ack_count": flow.ack_count,
        "fin_count": flow.fin_count,
        "rst_count": flow.rst_count,
        "psh_count": flow.psh_count,
        "urg_count": flow.urg_count,

        # ── TCP Flag Ratios ───────────────────────────────────────
        "syn_ratio": syn_ratio,
        "ack_ratio": ack_ratio,
        "fin_ratio": fin_ratio,
        "rst_ratio": rst_ratio,
        "psh_ratio": psh_ratio,
        "urg_ratio": urg_ratio,

        # ── Port Features ─────────────────────────────────────────
        "src_port":         flow.src_port,
        "dst_port":         flow.dst_port,
        "is_well_known_port": int(flow.dst_port < 1024 and flow.dst_port > 0),
        "dst_port_category": dst_port_cat,   # string — for display only

        # ── Label (to be filled by training pipeline in Phase 4) ──
        "label": "UNKNOWN",
    }

    # Merge one-hot port encoding into features
    features.update(dst_port_onehot)

    return features
