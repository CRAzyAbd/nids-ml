# main.py
"""
NIDS — Network Intrusion Detection System
Entry point.

Usage:
    sudo venv/bin/python3 main.py --mode capture
    python3 main.py --mode preprocess
    python3 main.py --mode eda
"""

import argparse
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.utils.logger import setup_logger
from config.settings import LOG_FILE, LOG_LEVEL, INTERFACE

logger = setup_logger("main", LOG_FILE, LOG_LEVEL)


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="NIDS — Network Intrusion Detection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  capture     Live packet capture + flow feature extraction (needs sudo)
  preprocess  Load CICIDS-2017 dataset and preprocess for ML
  eda         Run exploratory data analysis on the dataset

Examples:
  sudo venv/bin/python3 main.py --mode capture
  sudo venv/bin/python3 main.py --mode capture --interface wlan0
  python3 main.py --mode preprocess
  python3 main.py --mode eda
        """
    )
    parser.add_argument(
        "--mode", "-m",
        type=str,
        default="capture",
        choices=["capture", "preprocess", "eda"],
        help="Operating mode (default: capture)"
    )
    parser.add_argument(
        "--interface", "-i",
        type=str,
        default=INTERFACE,
        help=f"Network interface for capture (default: {INTERFACE})"
    )
    parser.add_argument(
        "--filter", "-f",
        type=str,
        default="",
        help='BPF filter string (e.g., "tcp", "not port 22")'
    )
    parser.add_argument(
        "--count", "-c",
        type=int,
        default=0,
        help="Packets to capture (0 = infinite)"
    )
    return parser.parse_args()


def check_root():
    if os.geteuid() != 0:
        logger.error("Capture mode requires root.")
        logger.error("Run: sudo venv/bin/python3 main.py --mode capture")
        sys.exit(1)


def main():
    args = parse_arguments()

    if args.mode == "capture":
        check_root()
        from src.sniffer.packet_capture import PacketCapture
        sniffer = PacketCapture(
            interface=args.interface,
            packet_filter=args.filter,
            packet_count=args.count,
        )
        sniffer.start()

    elif args.mode == "preprocess":
        from scripts.preprocess_data import main as run_preprocess
        run_preprocess()

    elif args.mode == "eda":
        from scripts.eda import run_eda
        run_eda()


if __name__ == "__main__":
    main()
