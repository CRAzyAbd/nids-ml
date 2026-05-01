# main.py
"""
NIDS — Network Intrusion Detection System

Usage:
    sudo venv/bin/python3 main.py --mode dashboard
    sudo venv/bin/python3 main.py --mode detect
    sudo venv/bin/python3 main.py --mode capture
    python3 main.py --mode train
    python3 main.py --mode preprocess
    python3 main.py --mode eda
"""

import argparse
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.utils.logger import setup_logger
from config.settings import LOG_FILE, LOG_LEVEL, INTERFACE, DASHBOARD_PORT

logger = setup_logger("main", LOG_FILE, LOG_LEVEL)


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="NIDS — Network Intrusion Detection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  dashboard  Live web dashboard at http://localhost:5001  (default)
  detect     Live detection with terminal alerts
  capture    Raw packet capture to CSV
  train      Train Random Forest + Isolation Forest models
  preprocess Load CICIDS-2017 dataset and preprocess for ML
  eda        Exploratory data analysis on the dataset

Examples:
  sudo venv/bin/python3 main.py
  sudo venv/bin/python3 main.py --mode dashboard
  sudo venv/bin/python3 main.py --mode dashboard --port 8080
  sudo venv/bin/python3 main.py --mode detect
  sudo venv/bin/python3 main.py --mode detect --interface wlan0
  python3 main.py --mode train
  python3 main.py --mode preprocess
  python3 main.py --mode eda
        """
    )
    parser.add_argument(
        "--mode", "-m",
        type=str,
        default="dashboard",
        choices=["capture", "detect", "dashboard", "preprocess", "eda", "train"],
        help="Operating mode (default: dashboard)"
    )
    parser.add_argument(
        "--interface", "-i",
        type=str,
        default=INTERFACE,
        help=f"Network interface (default: {INTERFACE})"
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
        help="Max packets to capture (0 = infinite)"
    )
    parser.add_argument(
        "--port", "-p",
        type=int,
        default=DASHBOARD_PORT,
        help=f"Dashboard port (default: {DASHBOARD_PORT})"
    )
    return parser.parse_args()


def check_root():
    if os.geteuid() != 0:
        logger.error("This mode requires root privileges for raw packet capture.")
        logger.error("Run: sudo venv/bin/python3 main.py")
        sys.exit(1)


def main():
    args = parse_arguments()

    if args.mode == "dashboard":
        check_root()
        from src.dashboard.app import run_dashboard
        run_dashboard(
            interface=args.interface,
            packet_filter=args.filter,
            port=args.port,
        )

    elif args.mode == "detect":
        check_root()
        from src.detection.detector     import RealTimeDetector
        from src.detection.alert_engine import AlertEngine
        from src.sniffer.packet_capture import PacketCapture

        detector     = RealTimeDetector()
        alert_engine = AlertEngine()

        if not detector.load_models():
            logger.error("Models missing. Run: python3 main.py --mode train")
            sys.exit(1)

        PacketCapture(
            interface=args.interface,
            packet_filter=args.filter,
            packet_count=args.count,
            mode="detect",
            detector=detector,
            alert_engine=alert_engine,
        ).start()

    elif args.mode == "capture":
        check_root()
        from src.sniffer.packet_capture import PacketCapture
        PacketCapture(
            interface=args.interface,
            packet_filter=args.filter,
            packet_count=args.count,
            mode="capture",
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
