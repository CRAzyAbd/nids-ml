# src/detection/detector.py
"""
Real-time inference engine for NIDS.

Loads the trained Random Forest and Isolation Forest from disk,
then classifies completed flows on demand.

Design decisions:
  - Models are loaded ONCE at startup (loading joblib on every flow
    would be catastrophically slow — ~500ms per load)
  - Scaler is also loaded once — must be the SAME scaler used in training
  - align_live_features() maps our live feature names to ML column order
  - We run BOTH models on every flow and combine their signals
  - A flow is flagged as an alert if:
      RF predicts non-BENIGN  OR  IF predicts ANOMALY

Confidence thresholds:
  - RF confidence < 0.6 → uncertain, downgrade to "SUSPICIOUS"
  - IF score < threshold → ANOMALY regardless of RF result
"""

import os
import sys
import numpy as np
import joblib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.models.random_forest    import NIDSRandomForest
from src.models.isolation_forest import NIDSIsolationForest
from src.data.feature_alignment  import align_live_features
from src.utils.logger import setup_logger
from config.settings import (
    LOG_FILE, LOG_LEVEL,
    RF_MODEL_PATH, ISO_MODEL_PATH,
    SCALER_PATH, FEATURE_COLS_PATH,
)

logger = setup_logger(__name__, LOG_FILE, LOG_LEVEL)

# Confidence below this → label as SUSPICIOUS instead of the predicted class
RF_CONFIDENCE_THRESHOLD = 0.60

# Alert levels
LEVEL_BENIGN    = "BENIGN"
LEVEL_SUSPICIOUS = "SUSPICIOUS"
LEVEL_ATTACK    = "ATTACK"
LEVEL_ANOMALY   = "ANOMALY"


class RealTimeDetector:
    """
    Loads trained models and classifies live network flows.

    Usage:
        detector = RealTimeDetector()
        detector.load_models()

        # For each completed flow:
        result = detector.classify(flow_feature_dict)
        # result is a DetectionResult with label, confidence, anomaly_score
    """

    def __init__(self):
        self.rf           = None
        self.iso          = None
        self.scaler       = None
        self.feature_cols = None
        self.is_ready     = False

    def load_models(self) -> bool:
        """
        Load all artifacts from disk.
        Returns True if successful, False if any file is missing.
        """
        missing = []
        for path in [RF_MODEL_PATH, ISO_MODEL_PATH, SCALER_PATH, FEATURE_COLS_PATH]:
            if not os.path.exists(path):
                missing.append(path)

        if missing:
            logger.error("Missing model files — run training first:")
            logger.error("  python3 main.py --mode train")
            for m in missing:
                logger.error(f"  Missing: {m}")
            return False

        logger.info("Loading models from disk...")

        # Load Random Forest
        self.rf = NIDSRandomForest()
        self.rf.load(RF_MODEL_PATH)
        logger.info(f"  ✓ Random Forest loaded "
                    f"({len(self.rf.label_names)} classes: {self.rf.label_names})")

        # Load Isolation Forest
        self.iso = NIDSIsolationForest()
        self.iso.load(ISO_MODEL_PATH)
        logger.info(f"  ✓ Isolation Forest loaded "
                    f"(threshold={self.iso.score_threshold:.4f})")

        # Load Scaler
        self.scaler = joblib.load(SCALER_PATH)
        logger.info(f"  ✓ StandardScaler loaded "
                    f"({len(self.scaler.mean_)} features)")

        # Load feature column list
        self.feature_cols = joblib.load(FEATURE_COLS_PATH)
        logger.info(f"  ✓ Feature list loaded ({len(self.feature_cols)} columns)")

        self.is_ready = True
        logger.info("  All models ready.\n")
        return True

    def classify(self, flow_features: dict) -> dict:
        """
        Classify a single completed flow.

        Args:
            flow_features: Dict from src.features.feature_extractor.extract_features()

        Returns:
            Detection result dict with keys:
              rf_label        : predicted class name (str)
              rf_confidence   : max class probability (float 0-1)
              rf_all_probs    : dict of class → probability
              iso_label       : "ANOMALY" or "NORMAL"
              iso_score       : raw anomaly score (float, lower=more anomalous)
              alert_level     : "BENIGN" / "SUSPICIOUS" / "ATTACK" / "ANOMALY"
              is_alert        : True if we should show an alert
              flow_summary    : human-readable flow description
        """
        if not self.is_ready:
            raise RuntimeError("Models not loaded. Call load_models() first.")

        # ── Align features ────────────────────────────────────────
        # Extract only the ML columns in the right order
        aligned = align_live_features(flow_features)
        X_raw = np.array(
            [aligned[col] for col in self.feature_cols],
            dtype=np.float32
        ).reshape(1, -1)

        # Replace any inf/nan with 0 (defensive)
        X_raw = np.nan_to_num(X_raw, nan=0.0, posinf=0.0, neginf=0.0)

        # ── Scale ─────────────────────────────────────────────────
        X_scaled = self.scaler.transform(X_raw)

        # ── Random Forest inference ───────────────────────────────
        rf_labels, rf_confidences = self.rf.predict(X_scaled)
        rf_label      = rf_labels[0]
        rf_confidence = float(rf_confidences[0])

        # All class probabilities
        rf_probs_raw = self.rf.model.predict_proba(X_scaled)[0]
        rf_all_probs = {
            name: float(prob)
            for name, prob in zip(self.rf.label_names, rf_probs_raw)
        }

        # ── Isolation Forest inference ────────────────────────────
        iso_labels, iso_scores = self.iso.predict(X_scaled)
        iso_label = iso_labels[0]
        iso_score = float(iso_scores[0])

        # ── Determine alert level ─────────────────────────────────
        is_alert    = False
        alert_level = LEVEL_BENIGN

        if rf_label != "BENIGN":
            if rf_confidence >= RF_CONFIDENCE_THRESHOLD:
                alert_level = LEVEL_ATTACK
                is_alert    = True
            else:
                # Low confidence non-benign prediction
                alert_level = LEVEL_SUSPICIOUS
                is_alert    = True

        elif iso_label == "ANOMALY":
            # RF says benign but IF disagrees — flag as anomaly
            alert_level = LEVEL_ANOMALY
            is_alert    = True

        # ── Build flow summary ────────────────────────────────────
        proto    = flow_features.get("flow_protocol", "?")
        src_ip   = flow_features.get("flow_src_ip",  "?")
        dst_ip   = flow_features.get("flow_dst_ip",  "?")
        src_port = flow_features.get("flow_src_port", 0)
        dst_port = flow_features.get("flow_dst_port", 0)
        pkts     = flow_features.get("total_packets", 0)
        bps      = flow_features.get("bytes_per_sec", 0)
        dur      = flow_features.get("duration", 0)

        flow_summary = (
            f"{proto} {src_ip}:{src_port} → {dst_ip}:{dst_port} "
            f"| {pkts}pkts | {bps:.0f}B/s | {dur:.2f}s"
        )

        return {
            "rf_label":      rf_label,
            "rf_confidence": rf_confidence,
            "rf_all_probs":  rf_all_probs,
            "iso_label":     iso_label,
            "iso_score":     iso_score,
            "iso_threshold": self.iso.score_threshold,
            "alert_level":   alert_level,
            "is_alert":      is_alert,
            "flow_summary":  flow_summary,
        }
