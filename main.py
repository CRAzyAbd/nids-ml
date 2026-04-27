# main.py
"""
NIDS — Network Intrusion Detection System

Usage:
    sudo venv/bin/python3 main.py --mode capture
    python3 main.py --mode preprocess
    python3 main.py --mode eda
    python3 main.py --mode train
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
  eda         Run exploratory data analysis
  train       Train Random Forest + Isolation Forest models

Examples:
  sudo venv/bin/python3 main.py --mode capture
  python3 main.py --mode preprocess
  python3 main.py --mode eda
  python3 main.py --mode train
        """
    )
    parser.add_argument("--mode", "-m", type=str, default="capture",
                        choices=["capture", "preprocess", "eda", "train"],
                        help="Operating mode")
    parser.add_argument("--interface", "-i", type=str, default=INTERFACE)
    parser.add_argument("--filter",    "-f", type=str, default="")
    parser.add_argument("--count",     "-c", type=int, default=0)
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
        PacketCapture(
            interface=args.interface,
            packet_filter=args.filter,
            packet_count=args.count,
        ).start()

    elif args.mode == "preprocess":
        from scripts.preprocess_data import main as run
        run()

    elif args.mode == "eda":
        from scripts.eda import run_eda
        run_eda()

    elif args.mode == "train":
        from scripts.train import main as run
        run()


if __name__ == "__main__":
    main()
