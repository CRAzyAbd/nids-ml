# src/models/random_forest.py
"""
Random Forest Classifier for NIDS.

WHY RANDOM FOREST?
  A Random Forest builds hundreds of decision trees, each trained on a
  random subset of rows and features. The final prediction is the majority
  vote across all trees. This gives us:

  - High accuracy on tabular data (consistently beats SVM, KNN on CICIDS)
  - Built-in feature importance scores (we can see WHICH features matter)
  - Robust to outliers (individual trees can be wrong, ensemble corrects)
  - No need for feature scaling (trees are threshold-based, not distance-based)
    — though we scale anyway for consistency with Isolation Forest

  On CICIDS-2017, a well-tuned RF achieves ~99% accuracy on known attacks.

TWO MODES:
  1. Binary classification  — BENIGN (0) vs ATTACK (1)
     Useful for simple alerting: "something is wrong"
  2. Multiclass classification — BENIGN / DoS / DDoS / PortScan / BruteForce / WebAttack
     Useful for triage: "here's what type of attack it is"
"""

import os
import time
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report, confusion_matrix,
    accuracy_score, f1_score, roc_auc_score,
)

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.utils.logger import setup_logger
from config.settings import (
    LOG_FILE, LOG_LEVEL, MODELS_DIR,
    RF_MODEL_PATH, RANDOM_STATE,
)

logger = setup_logger(__name__, LOG_FILE, LOG_LEVEL)


class NIDSRandomForest:
    """
    Wrapper around sklearn's RandomForestClassifier with
    training, evaluation, persistence, and prediction methods.
    """

    def __init__(self,
                 n_estimators: int = 100,
                 max_depth: int = None,
                 min_samples_split: int = 5,
                 n_jobs: int = -1,
                 random_state: int = RANDOM_STATE):
        """
        Args:
            n_estimators:      Number of trees in the forest.
                               More = better accuracy but slower.
                               100 is a good balance for this dataset size.
            max_depth:         Max depth of each tree. None = grow until
                               leaves are pure. Deeper = more accurate but
                               slower and more memory.
            min_samples_split: Min samples needed to split a node.
                               Higher = more regularization (less overfitting).
            n_jobs:            CPU cores to use. -1 = use all cores.
            random_state:      Seed for reproducibility.
        """
        self.model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            min_samples_split=min_samples_split,
            n_jobs=n_jobs,
            random_state=random_state,
            class_weight="balanced",  # compensates for class imbalance
            verbose=0,
        )
        self.feature_columns = None
        self.label_names = None
        self.is_trained = False

    def train(self,
              X_train: np.ndarray,
              y_train: np.ndarray,
              feature_columns: list,
              label_names: list) -> dict:
        """
        Train the Random Forest.

        Args:
            X_train:        Scaled feature matrix (rows=flows, cols=features)
            y_train:        Integer class labels
            feature_columns: List of feature names (same order as X_train cols)
            label_names:    List mapping int → class name

        Returns:
            Dict with training time and feature importances
        """
        self.feature_columns = feature_columns
        self.label_names = label_names

        logger.info(f"Training Random Forest...")
        logger.info(f"  Samples   : {X_train.shape[0]:,}")
        logger.info(f"  Features  : {X_train.shape[1]}")
        logger.info(f"  Classes   : {label_names}")
        logger.info(f"  Trees     : {self.model.n_estimators}")
        logger.info(f"  CPU cores : all available")

        start = time.time()
        self.model.fit(X_train, y_train)
        elapsed = time.time() - start

        self.is_trained = True
        logger.info(f"  Training complete in {elapsed:.1f} seconds")

        # Feature importances — which features the forest relies on most
        importances = dict(zip(
            feature_columns,
            self.model.feature_importances_
        ))
        top10 = sorted(importances.items(), key=lambda x: -x[1])[:10]
        logger.info("\n  Top 10 most important features:")
        for feat, imp in top10:
            bar = "█" * int(imp * 200)
            logger.info(f"    {feat:<30} {imp:.4f}  {bar}")

        return {
            "training_time_seconds": elapsed,
            "feature_importances": importances,
        }

    def evaluate(self,
                 X_test: np.ndarray,
                 y_test: np.ndarray) -> dict:
        """
        Evaluate the trained model on the test set.

        Returns a dict with all metrics.
        """
        if not self.is_trained:
            raise RuntimeError("Model not trained yet. Call train() first.")

        logger.info("\nEvaluating Random Forest on test set...")

        y_pred = self.model.predict(X_test)
        y_prob = self.model.predict_proba(X_test)

        accuracy  = accuracy_score(y_test, y_pred)
        f1_macro  = f1_score(y_test, y_pred, average="macro",  zero_division=0)
        f1_weighted = f1_score(y_test, y_pred, average="weighted", zero_division=0)

        logger.info(f"\n  Accuracy         : {accuracy:.4f}  ({accuracy*100:.2f}%)")
        logger.info(f"  F1 (macro)       : {f1_macro:.4f}")
        logger.info(f"  F1 (weighted)    : {f1_weighted:.4f}")

        # Full classification report (precision, recall, F1 per class)
        report = classification_report(
            y_test, y_pred,
            target_names=self.label_names,
            zero_division=0,
        )
        logger.info(f"\n  Classification Report:\n{report}")

        # Confusion matrix
        cm = confusion_matrix(y_test, y_pred)
        logger.info("  Confusion Matrix (rows=actual, cols=predicted):")
        header = "  " + "".join(f"{n[:6]:>8}" for n in self.label_names)
        logger.info(header)
        for i, row in enumerate(cm):
            row_str = "  " + f"{self.label_names[i][:10]:<12}" + \
                      "".join(f"{v:>8}" for v in row)
            logger.info(row_str)

        return {
            "accuracy":     accuracy,
            "f1_macro":     f1_macro,
            "f1_weighted":  f1_weighted,
            "report":       report,
            "confusion_matrix": cm,
            "y_pred":       y_pred,
            "y_prob":       y_prob,
        }

    def predict(self, X: np.ndarray) -> tuple:
        """
        Predict class for new samples.

        Returns:
            (predicted_labels, confidence_scores)
            predicted_labels: list of class name strings
            confidence_scores: max probability across all classes
        """
        if not self.is_trained:
            raise RuntimeError("Model not trained. Load or train first.")

        y_pred_int = self.model.predict(X)
        y_prob     = self.model.predict_proba(X)

        predicted_labels = [self.label_names[i] for i in y_pred_int]
        confidence       = np.max(y_prob, axis=1)

        return predicted_labels, confidence

    def save(self, path: str = RF_MODEL_PATH):
        """Save the trained model to disk."""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump({
            "model":           self.model,
            "feature_columns": self.feature_columns,
            "label_names":     self.label_names,
        }, path)
        size_mb = os.path.getsize(path) / 1e6
        logger.info(f"  Random Forest saved → {path} ({size_mb:.1f} MB)")

    def load(self, path: str = RF_MODEL_PATH):
        """Load a previously saved model from disk."""
        data = joblib.load(path)
        self.model          = data["model"]
        self.feature_columns = data["feature_columns"]
        self.label_names    = data["label_names"]
        self.is_trained     = True
        logger.info(f"  Random Forest loaded from {path}")
        return self

    def get_feature_importances(self) -> list:
        """Return feature importances sorted descending."""
        if not self.is_trained:
            return []
        pairs = list(zip(self.feature_columns, self.model.feature_importances_))
        return sorted(pairs, key=lambda x: -x[1])
