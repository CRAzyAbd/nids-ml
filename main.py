# main.py
"""
NIDS — Network Intrusion Detection System
Entry point for the application.

Usage:
    sudo python3 main.py
    sudo python3 main.py --interface wlan0
    sudo python3 main.py --interface eth0 --filter "tcp"
    sudo python3 main.py --interface eth0 --count 500
"""

import argparse
import sys
import os

# Add the project root to Python's import path
# This lets us import from src/, config/ etc. from anywhere
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.sniffer.packet_capture import PacketCapture
from src.utils.logger import setup_logger
from config.settings import LOG_FILE, LOG_LEVEL, INTERFACE

logger = setup_logger("main", LOG_FILE, LOG_LEVEL)


def parse_arguments():
    """
    Set up command-line argument parsing.
    argparse handles --flag style arguments automatically.
    """
    parser = argparse.ArgumentParser(
        description="NIDS — Network Intrusion Detection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 main.py
  sudo python3 main.py --interface wlan0
  sudo python3 main.py --interface eth0 --filter "tcp port 80"
  sudo python3 main.py --count 200
        """
    )

    parser.add_argument(
        "--interface", "-i",
        type=str,
        default=INTERFACE,
        help=f"Network interface to capture on (default: {INTERFACE})"
    )

    parser.add_argument(
        "--filter", "-f",
        type=str,
        default="",
        help='BPF filter string (e.g., "tcp", "port 80", "not port 22")'
    )

    parser.add_argument(
        "--count", "-c",
        type=int,
        default=0,
        help="Number of packets to capture (0 = infinite, default: 0)"
    )

    return parser.parse_args()


def check_root():
    """
    Warn the user if they're not running as root.
    Scapy needs root to open raw sockets.
    """
    if os.geteuid() != 0:
        logger.error("This program requires root privileges to capture packets.")
        logger.error("Please run: sudo python3 main.py")
        sys.exit(1)


def main():
    # Parse command-line arguments
    args = parse_arguments()

    # Check for root access
    check_root()

    # Create the sniffer with arguments (or defaults from settings.py)
    sniffer = PacketCapture(
        interface=args.interface,
        packet_filter=args.filter,
        packet_count=args.count,
    )

    # Start capturing!
    sniffer.start()


if __name__ == "__main__":
    main()
