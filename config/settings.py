# config/settings.py
"""
Central configuration for the NIDS project.
"""

import os

# ─── Project Root ────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ─── Network Interface ───────────────────────────────────────────
INTERFACE      = "ens33"   # ← change to your interface (ip link show)
CAPTURE_FILTER = ""
PACKET_COUNT   = 0

# ─── Flow Tracking ───────────────────────────────────────────────
FLOW_TIMEOUT          = 120
FLOW_EXPORT_INTERVAL  = 60
MIN_PACKETS_PER_FLOW  = 2

# ─── Port Categories ─────────────────────────────────────────────
PORT_CATEGORIES = {
    "web":      {80, 443, 8080, 8443},
    "dns":      {53},
    "mail":     {25, 465, 587, 110, 995, 143, 993},
    "ftp":      {20, 21},
    "ssh":      {22},
    "telnet":   {23},
    "smb":      {445, 139},
    "rdp":      {3389},
    "database": {3306, 5432, 1433, 27017, 6379},
    "ntp":      {123},
}

# ─── Logging ─────────────────────────────────────────────────────
LOG_DIR   = os.path.join(BASE_DIR, "logs")
LOG_FILE  = os.path.join(LOG_DIR, "nids.log")
LOG_LEVEL = "INFO"

# ─── Capture Output ──────────────────────────────────────────────
CAPTURED_DATA_DIR = os.path.join(BASE_DIR, "captured_data")
FLOWS_DATA_DIR    = os.path.join(BASE_DIR, "captured_data", "flows")

# ─── Display ─────────────────────────────────────────────────────
STATS_INTERVAL        = 50
FLOW_DISPLAY_INTERVAL = 10

# ─── Dataset Paths (Phase 3) ─────────────────────────────────────
DATA_DIR           = os.path.join(BASE_DIR, "data")
RAW_DATA_DIR       = os.path.join(DATA_DIR, "raw", "MachineLearningCVE")
PROCESSED_DATA_DIR = os.path.join(DATA_DIR, "processed")
REPORTS_DIR        = os.path.join(DATA_DIR, "reports")

# All 8 files from the zip
CICIDS_FILES = [
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
]

# ─── Preprocessing (Phase 3) ─────────────────────────────────────
TEST_SIZE        = 0.20
RANDOM_STATE     = 42
MAX_BENIGN_ROWS  = 100_000
MAX_ATTACK_ROWS  = 20_000

# ─── Models (Phase 4) ────────────────────────────────────────────
MODELS_DIR        = os.path.join(BASE_DIR, "models")
SCALER_PATH       = os.path.join(MODELS_DIR, "scaler.joblib")
ENCODER_PATH      = os.path.join(MODELS_DIR, "label_encoder.joblib")
RF_MODEL_PATH     = os.path.join(MODELS_DIR, "random_forest.joblib")
ISO_MODEL_PATH    = os.path.join(MODELS_DIR, "isolation_forest.joblib")
FEATURE_COLS_PATH = os.path.join(MODELS_DIR, "feature_columns.joblib")

# ─── Isolation Forest Tuning ─────────────────────────────────────
# contamination = expected fraction of anomalies in the dataset
# Higher value = more sensitive = catches more attacks but more false alarms
# 0.15 means "expect up to 15% of flows to be anomalous"
IF_CONTAMINATION = 0.15
