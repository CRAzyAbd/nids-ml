# src/utils/logger.py
"""
Logger utility for NIDS.
Creates a logger that:
  - Prints colored messages to the terminal
  - Simultaneously writes to a log file
"""

import logging
import os
from datetime import datetime
from colorama import Fore, Style, init

# Initialize colorama (required on Windows; harmless on Linux)
init(autoreset=True)


class ColoredFormatter(logging.Formatter):
    """
    A custom log formatter that adds color to terminal output
    based on the log level.
    """

    # Map each log level to a color
    LEVEL_COLORS = {
        logging.DEBUG:    Fore.CYAN,
        logging.INFO:     Fore.GREEN,
        logging.WARNING:  Fore.YELLOW,
        logging.ERROR:    Fore.RED,
        logging.CRITICAL: Fore.MAGENTA,
    }

    def format(self, record):
        # Get the color for this log level
        color = self.LEVEL_COLORS.get(record.levelno, Fore.WHITE)

        # Format the timestamp nicely
        timestamp = datetime.fromtimestamp(record.created).strftime("%Y-%m-%d %H:%M:%S")

        # Build the colored output line
        # Style.BRIGHT makes text bold, Style.RESET_ALL clears all formatting
        formatted = (
            f"{Fore.WHITE}[{timestamp}] "
            f"{color}{Style.BRIGHT}{record.levelname:<8}{Style.RESET_ALL} "
            f"{Fore.WHITE}{record.getMessage()}"
        )
        return formatted


class PlainFormatter(logging.Formatter):
    """
    Plain (no color) formatter for file output.
    Color codes look like garbage in log files.
    """

    def format(self, record):
        timestamp = datetime.fromtimestamp(record.created).strftime("%Y-%m-%d %H:%M:%S")
        return f"[{timestamp}] {record.levelname:<8} {record.getMessage()}"


def setup_logger(name: str, log_file: str, level: str = "INFO") -> logging.Logger:
    """
    Create and return a configured logger.

    Args:
        name:     Logger name (usually __name__ of the calling module)
        log_file: Full path to the log file
        level:    Logging level as string ("DEBUG", "INFO", etc.)

    Returns:
        A configured logging.Logger instance
    """

    # Convert the level string to a logging constant (e.g., "INFO" → 20)
    numeric_level = getattr(logging, level.upper(), logging.INFO)

    # Create the logger
    logger = logging.getLogger(name)
    logger.setLevel(numeric_level)

    # Avoid adding duplicate handlers if this function is called multiple times
    if logger.handlers:
        return logger

    # ── Terminal Handler (with colors) ──────────────────────────
    console_handler = logging.StreamHandler()
    console_handler.setLevel(numeric_level)
    console_handler.setFormatter(ColoredFormatter())

    # ── File Handler (no colors) ─────────────────────────────────
    # Ensure the logs directory exists
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(numeric_level)
    file_handler.setFormatter(PlainFormatter())

    # Attach both handlers to the logger
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    return logger
