# src/detection/alert_engine.py
"""
Alert Engine — formats, displays, and logs detection results.

Terminal output uses ANSI color codes:
  GREEN  → BENIGN traffic (shown briefly, not stored as alerts)
  YELLOW → SUSPICIOUS (low-confidence non-benign RF prediction)
  RED    → ATTACK (high-confidence RF detection)
  MAGENTA → ANOMALY (Isolation Forest flagged, RF said benign)

All alerts (non-BENIGN) are written to logs/alerts.log
Running statistics are printed every N flows.
"""

import os
import csv
import time
from datetime import datetime
from collections import defaultdict

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.utils.logger import setup_logger
from config.settings import LOG_FILE, LOG_LEVEL, LOG_DIR

logger = setup_logger(__name__, LOG_FILE, LOG_LEVEL)

# ANSI color codes
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
RED     = "\033[91m"
MAGENTA = "\033[95m"
CYAN    = "\033[96m"
BOLD    = "\033[1m"
RESET   = "\033[0m"

# How often to print running stats
STATS_EVERY_N_FLOWS = 20


class AlertEngine:
    """
    Receives detection results and handles display + logging.

    Tracks:
      - Total flows classified
      - Alert counts per label
      - Running detection rate
    """

    def __init__(self):
        self.total_flows   = 0
        self.total_alerts  = 0
        self.label_counts  = defaultdict(int)
        self.alert_counts  = defaultdict(int)
        self.session_start = time.time()

        # Set up alerts CSV log
        os.makedirs(LOG_DIR, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.alert_log_path = os.path.join(LOG_DIR, f"alerts_{timestamp}.csv")
        self._alert_csv     = open(self.alert_log_path, "w", newline="")
        self._alert_writer  = None   # initialized on first alert

        logger.info(f"AlertEngine initialized → alerts log: {self.alert_log_path}")

    def process(self, detection_result: dict):
        """
        Handle one detection result.

        Args:
            detection_result: Dict returned by RealTimeDetector.classify()
        """
        self.total_flows += 1
        label       = detection_result["rf_label"]
        alert_level = detection_result["alert_level"]
        is_alert    = detection_result["is_alert"]

        self.label_counts[label] += 1

        if is_alert:
            self.total_alerts += 1
            self.alert_counts[alert_level] += 1
            self._display_alert(detection_result)
            self._log_alert(detection_result)
        else:
            # Show benign flows briefly (every 5th one to avoid flooding)
            if self.total_flows % 5 == 0:
                self._display_benign(detection_result)

        # Periodic stats
        if self.total_flows % STATS_EVERY_N_FLOWS == 0:
            self._print_stats()

    def _display_alert(self, r: dict):
        """Print a highlighted alert line to terminal."""
        level = r["alert_level"]
        label = r["rf_label"]
        conf  = r["rf_confidence"]
        iso   = r["iso_label"]
        score = r["iso_score"]
        summary = r["flow_summary"]

        if level == "ATTACK":
            color  = RED
            symbol = "🚨"
        elif level == "ANOMALY":
            color  = MAGENTA
            symbol = "⚠️ "
        else:
            color  = YELLOW
            symbol = "❓"

        timestamp = datetime.now().strftime("%H:%M:%S")

        print(
            f"\n{color}{BOLD}"
            f"[{timestamp}] {symbol} {level}"
            f"{RESET}"
        )
        print(f"  {color}Flow    : {summary}{RESET}")

        if level == "ATTACK":
            print(f"  {color}RF      : {label} (confidence: {conf:.1%}){RESET}")
        elif level == "ANOMALY":
            print(f"  {color}RF      : {label} (conf: {conf:.1%}) — but IF flagged anomaly{RESET}")
            print(f"  {color}IF Score: {score:.4f} (threshold: {r.get('iso_threshold','?')}){RESET}")
        else:
            # SUSPICIOUS
            print(f"  {color}RF      : {label} (LOW confidence: {conf:.1%}){RESET}")
            print(f"  {color}IF      : {iso}{RESET}")

        # Show top 3 class probabilities for context
        probs = sorted(r["rf_all_probs"].items(), key=lambda x: -x[1])[:3]
        prob_str = "  ".join(f"{k}:{v:.1%}" for k, v in probs)
        print(f"  {CYAN}Probs   : {prob_str}{RESET}")

    def _display_benign(self, r: dict):
        """Print a brief benign flow line."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        summary   = r["flow_summary"]
        conf      = r["rf_confidence"]
        print(
            f"{GREEN}[{timestamp}] ✓ BENIGN  "
            f"{summary}  (conf: {conf:.1%}){RESET}"
        )

    def _log_alert(self, r: dict):
        """Write alert to CSV log file."""
        row = {
            "timestamp":     datetime.now().isoformat(),
            "alert_level":   r["alert_level"],
            "rf_label":      r["rf_label"],
            "rf_confidence": round(r["rf_confidence"], 4),
            "iso_label":     r["iso_label"],
            "iso_score":     round(r["iso_score"], 4),
            "flow_summary":  r["flow_summary"],
        }

        if self._alert_writer is None:
            self._alert_writer = csv.DictWriter(
                self._alert_csv, fieldnames=list(row.keys())
            )
            self._alert_writer.writeheader()

        self._alert_writer.writerow(row)
        self._alert_csv.flush()

    def _print_stats(self):
        """Print running detection statistics."""
        elapsed = time.time() - self.session_start
        rate    = self.total_alerts / max(self.total_flows, 1) * 100

        print(f"\n{CYAN}{'─'*60}")
        print(f"  DETECTION STATS  |  "
              f"Flows: {self.total_flows}  |  "
              f"Alerts: {self.total_alerts} ({rate:.1f}%)  |  "
              f"Uptime: {elapsed:.0f}s")
        print(f"{'─'*60}")

        # Label breakdown
        for label, count in sorted(self.label_counts.items(), key=lambda x: -x[1]):
            pct = count / max(self.total_flows, 1) * 100
            bar = "█" * int(pct / 3)
            color = GREEN if label == "BENIGN" else RED
            print(f"  {color}{label:<14}{RESET}  {count:>5}  ({pct:5.1f}%)  {bar}")

        print(f"{'─'*60}{RESET}\n")

    def print_final_summary(self):
        """Print session summary when capture ends."""
        elapsed = time.time() - self.session_start

        print(f"\n{BOLD}{'='*60}")
        print(f"  NIDS SESSION SUMMARY")
        print(f"{'='*60}{RESET}")
        print(f"  Duration        : {elapsed:.0f} seconds")
        print(f"  Total flows     : {self.total_flows:,}")
        print(f"  Total alerts    : {self.total_alerts:,}")
        print(f"  Detection rate  : {self.total_alerts/max(self.total_flows,1)*100:.1f}%")
        print(f"\n  Alerts by level:")
        for level, count in sorted(self.alert_counts.items(), key=lambda x: -x[1]):
            print(f"    {level:<15} {count:,}")
        print(f"\n  Alert log saved → {self.alert_log_path}")
        print(f"{'='*60}\n")

        self._alert_csv.close()

    def get_stats(self) -> dict:
        return {
            "total_flows":  self.total_flows,
            "total_alerts": self.total_alerts,
            "label_counts": dict(self.label_counts),
            "alert_counts": dict(self.alert_counts),
        }
