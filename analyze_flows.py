# analyze_flows.py
"""
Quick analysis of captured flow features.
Run AFTER a capture session to inspect what was collected.

Usage:
    python3 analyze_flows.py
    python3 analyze_flows.py --file captured_data/flows/flows_20250425_143211.csv
"""

import os
import glob
import argparse
import pandas as pd
import numpy as np

def find_latest_flow_file() -> str:
    """Find the most recently created flow CSV."""
    files = glob.glob("captured_data/flows/flows_*.csv")
    if not files:
        return None
    return max(files, key=os.path.getctime)

def analyze(filepath: str):
    print(f"\n{'='*65}")
    print(f"  FLOW FEATURE ANALYSIS")
    print(f"  File: {filepath}")
    print(f"{'='*65}\n")

    df = pd.read_csv(filepath)
    print(f"  Total flows: {len(df)}")
    print(f"  Total columns (features): {len(df.columns)}\n")

    # Protocol breakdown
    print("── Protocol Distribution ────────────────────────────────────")
    if "flow_protocol" in df.columns:
        proto_counts = df["flow_protocol"].value_counts()
        for proto, count in proto_counts.items():
            bar = "█" * (count * 30 // max(proto_counts))
            print(f"  {proto:<8} {count:>4} flows  {bar}")
    print()

    # Port category breakdown
    print("── Destination Port Categories ──────────────────────────────")
    if "dst_port_category" in df.columns:
        cat_counts = df["dst_port_category"].value_counts()
        for cat, count in cat_counts.items():
            bar = "█" * (count * 30 // max(cat_counts))
            print(f"  {cat:<12} {count:>4} flows  {bar}")
    print()

    # Key numerical stats
    numeric_cols = [
        "duration", "total_packets", "total_bytes",
        "bytes_per_sec", "pkts_per_sec",
        "fwd_iat_mean", "syn_ratio", "ack_ratio", "rst_ratio"
    ]
    available = [c for c in numeric_cols if c in df.columns]
    print("── Key Feature Statistics ───────────────────────────────────")
    print(df[available].describe().round(4).to_string())
    print()

    # Potential anomalies (for illustration — no model yet)
    print("── Anomaly Hints (rule-based, pre-ML) ───────────────────────")
    if "syn_ratio" in df.columns:
        scan_candidates = df[df["syn_ratio"] > 0.8]
        print(f"  High SYN ratio (>0.8) flows: {len(scan_candidates)}"
              f"  ← potential port scan indicator")

    if "bytes_per_sec" in df.columns:
        fast_flows = df[df["bytes_per_sec"] > df["bytes_per_sec"].quantile(0.95)]
        print(f"  Top 5%% by bytes/sec flows:   {len(fast_flows)}"
              f"  ← potential high-volume traffic")

    if "rst_ratio" in df.columns:
        rst_flows = df[df["rst_ratio"] > 0.5]
        print(f"  High RST ratio (>0.5) flows: {len(rst_flows)}"
              f"  ← potential connection refusals/scans")
    print()

    print(f"{'='*65}\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze captured flow features")
    parser.add_argument("--file", "-f", type=str, default=None,
                        help="Flow CSV file (default: most recent)")
    args = parser.parse_args()

    filepath = args.file or find_latest_flow_file()
    if not filepath:
        print("No flow files found. Run a capture first:")
        print("  sudo venv/bin/python3 main.py --count 200")
        exit(1)

    analyze(filepath)
