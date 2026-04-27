# scripts/train.py
"""
Full model training pipeline for NIDS Phase 4.

Loads preprocessed data → trains RF + IF → evaluates → saves models + charts.

Usage:
    python3 main.py --mode train
    python3 scripts/train.py
"""

import os
import sys
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.models.random_forest    import NIDSRandomForest
from src.models.isolation_forest import NIDSIsolationForest
from src.models.evaluator        import (
    plot_confusion_matrix,
    plot_feature_importance,
    plot_anomaly_scores,
    save_training_report,
)
from src.utils.logger import setup_logger
from config.settings import (
    LOG_FILE, LOG_LEVEL,
    PROCESSED_DATA_DIR, MODELS_DIR,
    RF_MODEL_PATH, ISO_MODEL_PATH,
    FEATURE_COLS_PATH, ENCODER_PATH,
)
import joblib

logger = setup_logger(__name__, LOG_FILE, LOG_LEVEL)


def load_processed_data():
    """Load the train/test CSVs produced by Phase 3 preprocessor."""
    train_path = os.path.join(PROCESSED_DATA_DIR, "features_train.csv")
    test_path  = os.path.join(PROCESSED_DATA_DIR, "features_test.csv")
    names_path = os.path.join(PROCESSED_DATA_DIR, "label_names.csv")

    for p in [train_path, test_path, names_path]:
        if not os.path.exists(p):
            logger.error(f"Missing: {p}")
            logger.error("Run: python3 main.py --mode preprocess")
            sys.exit(1)

    train = pd.read_csv(train_path)
    test  = pd.read_csv(test_path)
    names = pd.read_csv(names_path)

    feature_columns = joblib.load(FEATURE_COLS_PATH)
    label_names     = names["label_name"].tolist()

    X_train = train[feature_columns].values.astype(np.float32)
    X_test  = test[feature_columns].values.astype(np.float32)
    y_train_multi  = train["label_multi"].values
    y_test_multi   = test["label_multi"].values
    y_train_binary = train["label_binary"].values
    y_test_binary  = test["label_binary"].values

    logger.info(f"Loaded train: {X_train.shape}  test: {X_test.shape}")
    logger.info(f"Classes: {label_names}")

    return (X_train, X_test,
            y_train_multi, y_test_multi,
            y_train_binary, y_test_binary,
            feature_columns, label_names)


def main():
    logger.info("=" * 65)
    logger.info("  NIDS — Phase 4: Model Training")
    logger.info("=" * 65)

    os.makedirs(MODELS_DIR, exist_ok=True)

    # ── Load data ─────────────────────────────────────────────────
    logger.info("\n[1/6] Loading preprocessed data...")
    (X_train, X_test,
     y_train_multi, y_test_multi,
     y_train_binary, y_test_binary,
     feature_columns, label_names) = load_processed_data()

    # ── Train Random Forest ───────────────────────────────────────
    logger.info("\n[2/6] Training Random Forest classifier...")
    rf = NIDSRandomForest(
        n_estimators=100,
        min_samples_split=5,
        n_jobs=-1,
    )
    rf_train_info = rf.train(
        X_train, y_train_multi,
        feature_columns, label_names
    )

    # ── Evaluate Random Forest ────────────────────────────────────
    logger.info("\n[3/6] Evaluating Random Forest...")
    rf_metrics = rf.evaluate(X_test, y_test_multi)

    # ── Train Isolation Forest ────────────────────────────────────
    logger.info("\n[4/6] Training Isolation Forest...")
    iso = NIDSIsolationForest(
        n_estimators=100,
        contamination=0.05,
    )
    iso.train(X_train, y_train_binary, feature_columns)

    # ── Evaluate Isolation Forest ─────────────────────────────────
    logger.info("\n[5/6] Evaluating Isolation Forest...")
    iso_metrics = iso.evaluate(X_test, y_test_binary)

    # ── Save Everything ───────────────────────────────────────────
    logger.info("\n[6/6] Saving models and evaluation charts...")

    rf.save(RF_MODEL_PATH)
    iso.save(ISO_MODEL_PATH)

    # Confusion matrix
    plot_confusion_matrix(
        rf_metrics["confusion_matrix"],
        label_names,
    )

    # Feature importance
    plot_feature_importance(
        rf.get_feature_importances(),
        top_n=20,
    )

    # Anomaly score distribution
    plot_anomaly_scores(
        iso_metrics["scores"],
        y_test_binary,
        iso.score_threshold,
    )

    # Text report
    save_training_report(rf_metrics, iso_metrics, label_names)

    # ── Final Summary ─────────────────────────────────────────────
    logger.info("\n" + "=" * 65)
    logger.info("  TRAINING COMPLETE — SUMMARY")
    logger.info("=" * 65)
    logger.info(f"\n  Random Forest:")
    logger.info(f"    Accuracy     : {rf_metrics['accuracy']*100:.2f}%")
    logger.info(f"    F1 (macro)   : {rf_metrics['f1_macro']:.4f}")
    logger.info(f"    F1 (weighted): {rf_metrics['f1_weighted']:.4f}")
    logger.info(f"\n  Isolation Forest:")
    logger.info(f"    Detection    : {iso_metrics['detection_rate']*100:.1f}% of attacks")
    logger.info(f"    False Alarms : {iso_metrics['false_alarm_rate']*100:.1f}% of benign")
    logger.info(f"\n  Models saved to  : {MODELS_DIR}/")
    logger.info(f"  Charts saved to  : data/reports/")
    logger.info("\n  Ready for Phase 5 — Real-Time Detection!")
    logger.info("=" * 65)


if __name__ == "__main__":
    main()
