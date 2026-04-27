# src/models/isolation_forest.py
"""
Isolation Forest anomaly detector for NIDS.

WHY ISOLATION FOREST?
  Unlike supervised models, Isolation Forest learns WITHOUT labels.
  It works on a beautifully simple insight:

  Anomalies are EASY TO ISOLATE.

  The algorithm builds random trees by repeatedly picking a random
  feature and a random split point. Normal points (BENIGN traffic)
  are densely clustered — it takes MANY splits to isolate them.
  Anomalous points (attacks) sit in sparse regions — they get
  isolated in VERY FEW splits.

  The anomaly score is based on the average depth needed to isolate
  a point across all trees. Short path = anomaly.

TRAINING STRATEGY:
  We train ONLY on BENIGN flows. The model has never seen attack data.
  At inference time, it flags anything that doesn't look like the
  normal traffic it was trained on.

  This makes it powerful against zero-day attacks — novel attacks
  that no labeled dataset has ever seen. The Random Forest won't
  recognize them (it only knows what it's been trained on), but
  Isolation Forest will flag them as anomalous.

OUTPUT:
  score:  A float in [-1, 1]. More negative = more anomalous.
  label:  "ANOMALY" or "NORMAL"
  The threshold (contamination) controls sensitivity.
"""

import os
import time
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.utils.logger import setup_logger
from config.settings import (
    LOG_FILE, LOG_LEVEL,
    ISO_MODEL_PATH, RANDOM_STATE,
)

logger = setup_logger(__name__, LOG_FILE, LOG_LEVEL)


class NIDSIsolationForest:
    """
    Isolation Forest wrapper for unsupervised anomaly detection.
    Trained only on BENIGN traffic, detects deviations at inference.
    """

    def __init__(self,
                 n_estimators: int = 100,
                 contamination: float = 0.05,
                 max_samples: str = "auto",
                 random_state: int = RANDOM_STATE):
        """
        Args:
            n_estimators:   Number of isolation trees.
            contamination:  Expected fraction of anomalies in training data.
                            Since we train on BENIGN-only, this should be low.
                            0.05 = we expect up to 5% of "benign" flows to
                            actually be mislabeled or borderline.
                            Lower = more strict (more false positives).
                            Higher = more lenient (more false negatives).
            max_samples:    "auto" uses min(256, n_samples). Increasing this
                            improves accuracy at the cost of speed.
        """
        self.model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            max_samples=max_samples,
            random_state=random_state,
            n_jobs=-1,
        )
        self.contamination  = contamination
        self.feature_columns = None
        self.is_trained     = False

        # Thresholds computed from training data
        self.score_threshold = None

    def train(self,
              X_train: np.ndarray,
              y_train_binary: np.ndarray,
              feature_columns: list) -> dict:
        """
        Train on BENIGN flows only.

        Args:
            X_train:         Full training feature matrix
            y_train_binary:  Binary labels (0=BENIGN, 1=ATTACK)
            feature_columns: Feature names

        Returns:
            Dict with training stats
        """
        self.feature_columns = feature_columns

        # Filter to BENIGN only
        benign_mask = (y_train_binary == 0)
        X_benign    = X_train[benign_mask]

        logger.info(f"Training Isolation Forest on BENIGN traffic only...")
        logger.info(f"  BENIGN samples : {X_benign.shape[0]:,}")
        logger.info(f"  Features       : {X_benign.shape[1]}")
        logger.info(f"  Trees          : {self.model.n_estimators}")
        logger.info(f"  Contamination  : {self.contamination}")

        start = time.time()
        self.model.fit(X_benign)
        elapsed = time.time() - start

        self.is_trained = True
        logger.info(f"  Training complete in {elapsed:.1f} seconds")

        # Compute anomaly scores on benign training data
        # score_samples returns raw scores (more negative = more anomalous)
        benign_scores = self.model.score_samples(X_benign)
        self.score_threshold = np.percentile(benign_scores, 5)

        logger.info(f"\n  Anomaly score stats on BENIGN training data:")
        logger.info(f"    Mean  : {benign_scores.mean():.4f}")
        logger.info(f"    Std   : {benign_scores.std():.4f}")
        logger.info(f"    Min   : {benign_scores.min():.4f}")
        logger.info(f"    5th % : {self.score_threshold:.4f}  ← anomaly threshold")

        return {
            "training_time_seconds": elapsed,
            "benign_samples_used":   X_benign.shape[0],
            "score_threshold":       self.score_threshold,
        }

    def evaluate(self,
                 X_test: np.ndarray,
                 y_test_binary: np.ndarray) -> dict:
        """
        Evaluate on test set.

        Note: Isolation Forest is unsupervised, so "evaluation" here
        means checking how well it separates BENIGN from ATTACK
        using only its anomaly scores — no labels used during training.
        """
        if not self.is_trained:
            raise RuntimeError("Model not trained yet.")

        logger.info("\nEvaluating Isolation Forest on test set...")

        # predict() returns 1 (normal) or -1 (anomaly)
        raw_preds   = self.model.predict(X_test)
        scores      = self.model.score_samples(X_test)

        # Convert: sklearn uses 1=normal, -1=anomaly
        # We convert to our convention: 0=BENIGN, 1=ANOMALY
        y_pred_binary = (raw_preds == -1).astype(int)

        # Count results
        n_total   = len(y_test_binary)
        n_benign  = (y_test_binary == 0).sum()
        n_attack  = (y_test_binary == 1).sum()

        # True positives: attacks correctly flagged as anomalies
        tp = ((y_pred_binary == 1) & (y_test_binary == 1)).sum()
        # True negatives: benign correctly flagged as normal
        tn = ((y_pred_binary == 0) & (y_test_binary == 0)).sum()
        # False positives: benign incorrectly flagged as anomaly
        fp = ((y_pred_binary == 1) & (y_test_binary == 0)).sum()
        # False negatives: attacks missed (flagged as normal)
        fn = ((y_pred_binary == 0) & (y_test_binary == 1)).sum()

        detection_rate = tp / max(n_attack, 1)   # recall on attacks
        false_alarm    = fp / max(n_benign, 1)    # FPR on benign
        precision      = tp / max(tp + fp, 1)

        logger.info(f"\n  Test set: {n_total:,} flows "
                    f"({n_benign:,} BENIGN, {n_attack:,} ATTACK)")
        logger.info(f"\n  Results:")
        logger.info(f"    True Positives  (attacks caught)  : {tp:>6,}")
        logger.info(f"    True Negatives  (benign correct)  : {tn:>6,}")
        logger.info(f"    False Positives (benign flagged)  : {fp:>6,}")
        logger.info(f"    False Negatives (attacks missed)  : {fn:>6,}")
        logger.info(f"\n  Detection Rate  (Recall)  : {detection_rate:.4f} "
                    f"({detection_rate*100:.1f}% of attacks caught)")
        logger.info(f"  False Alarm Rate          : {false_alarm:.4f} "
                    f"({false_alarm*100:.1f}% of benign flagged)")
        logger.info(f"  Precision                 : {precision:.4f}")

        return {
            "detection_rate":  detection_rate,
            "false_alarm_rate": false_alarm,
            "precision":       precision,
            "tp": tp, "tn": tn, "fp": fp, "fn": fn,
            "y_pred_binary":   y_pred_binary,
            "scores":          scores,
        }

    def predict(self, X: np.ndarray) -> tuple:
        """
        Predict anomaly for new samples.

        Returns:
            (labels, scores)
            labels: list of "ANOMALY" or "NORMAL"
            scores: raw anomaly scores (lower = more anomalous)
        """
        if not self.is_trained:
            raise RuntimeError("Model not trained. Load or train first.")

        raw    = self.model.predict(X)
        scores = self.model.score_samples(X)
        labels = ["ANOMALY" if r == -1 else "NORMAL" for r in raw]

        return labels, scores

    def get_anomaly_score(self, X: np.ndarray) -> np.ndarray:
        """Return raw anomaly scores. More negative = more anomalous."""
        return self.model.score_samples(X)

    def save(self, path: str = ISO_MODEL_PATH):
        """Save the trained model to disk."""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump({
            "model":            self.model,
            "feature_columns":  self.feature_columns,
            "score_threshold":  self.score_threshold,
            "contamination":    self.contamination,
        }, path)
        size_mb = os.path.getsize(path) / 1e6
        logger.info(f"  Isolation Forest saved → {path} ({size_mb:.1f} MB)")

    def load(self, path: str = ISO_MODEL_PATH):
        """Load a previously saved model from disk."""
        data = joblib.load(path)
        self.model           = data["model"]
        self.feature_columns = data["feature_columns"]
        self.score_threshold = data["score_threshold"]
        self.contamination   = data["contamination"]
        self.is_trained      = True
        logger.info(f"  Isolation Forest loaded from {path}")
        return self
