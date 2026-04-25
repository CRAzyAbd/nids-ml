# main.py
"""
NIDS — Network Intrusion Detection System
Entry point.

Usage:
    sudo venv/bin/python3 main.py
    sudo venv/bin/python3 main.py --interface wlan0
    sudo venv/bin/python3 main.py --filter "tcp" --count 500
"""

import argparse
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.sniffer.packet_capture import PacketCapture
from src.utils.logger import setup_logger
from config.settings import LOG_FILE, LOG_LEVEL, INTERFACE

logger = setup_logger("main", LOG_FILE, LOG_LEVEL)


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="NIDS — Network Intrusion Detection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  capture   Live packet capture + flow feature extraction (default)

Examples:
  sudo venv/bin/python3 main.py
  sudo venv/bin/python3 main.py --interface wlan0
  sudo venv/bin/python3 main.py --filter "tcp" --count 500
  sudo venv/bin/python3 main.py --count 200 --interface eth0
        """
    )
    parser.add_argument("--interface", "-i", type=str, default=INTERFACE,
                        help=f"Network interface (default: {INTERFACE})")
    parser.add_argument("--filter", "-f", type=str, default="",
                        help='BPF filter (e.g., "tcp", "port 80", "not port 22")')
    parser.add_argument("--count", "-c", type=int, default=0,
                        help="Packets to capture (0 = infinite)")
    parser.add_argument("--mode", "-m", type=str, default="capture",
                        choices=["capture"],
                        help="Mode: capture (more modes coming in later phases)")
    return parser.parse_args()


def check_root():
    if os.geteuid() != 0:
        logger.error("Root required for raw packet capture.")
        logger.error("Run: sudo venv/bin/python3 main.py")
        sys.exit(1)


def main():
    args = parse_arguments()
    check_root()

    if args.mode == "capture":
        sniffer = PacketCapture(
            interface=args.interface,
            packet_filter=args.filter,
            packet_count=args.count,
        )
        sniffer.start()


if __name__ == "__main__":
    main()
