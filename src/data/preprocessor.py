import os
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.data.feature_alignment import ML_FEATURE_COLUMNS, BINARY_LABEL_MAP
from src.utils.logger import setup_logger
from config.settings import (
    LOG_FILE, LOG_LEVEL, PROCESSED_DATA_DIR, MODELS_DIR,
    TEST_SIZE, RANDOM_STATE, SCALER_PATH, ENCODER_PATH, FEATURE_COLS_PATH,
)

logger = setup_logger(__name__, LOG_FILE, LOG_LEVEL)


def preprocess(df):
    logger.info("=" * 65)
    logger.info("  PREPROCESSOR")
    logger.info("=" * 65)
    os.makedirs(PROCESSED_DATA_DIR, exist_ok=True)
    os.makedirs(MODELS_DIR, exist_ok=True)

    # Add missing columns
    for col in ML_FEATURE_COLUMNS:
        if col not in df.columns:
            df[col] = 0.0

    # Drop NaN/Inf
    df = df.replace([np.inf, -np.inf], np.nan)
    feat_present = [c for c in ML_FEATURE_COLUMNS if c in df.columns]
    before = len(df)
    df = df.dropna(subset=feat_present)
    logger.info(f"Dropped {before - len(df):,} bad rows. Remaining: {len(df):,}")

    # Encode labels
    df["label_binary"] = df["label"].map(BINARY_LABEL_MAP).fillna(1).astype(int)
    le = LabelEncoder()
    df["label_multi"] = le.fit_transform(df["label"])
    label_names = list(le.classes_)
    logger.info(f"Classes: {label_names}")

    counts = df["label"].value_counts()
    for label, count in counts.items():
        pct = count / len(df) * 100
        logger.info(f"  {label:<20} {count:>8,} ({pct:.1f}%)")

    # Split
    X = df[ML_FEATURE_COLUMNS].values.astype(np.float32)
    y_bin = df["label_binary"].values
    y_mul = df["label_multi"].values
    X_train, X_test, y_train_b, y_test_b, y_train_m, y_test_m = train_test_split(
        X, y_bin, y_mul, test_size=TEST_SIZE,
        random_state=RANDOM_STATE, stratify=y_bin,
    )
    logger.info(f"Train: {X_train.shape[0]:,}  Test: {X_test.shape[0]:,}")

    # Scale
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s  = scaler.transform(X_test)

    # Save CSVs
    train_df = pd.DataFrame(X_train_s, columns=ML_FEATURE_COLUMNS)
    train_df["label_binary"] = y_train_b
    train_df["label_multi"]  = y_train_m
    train_df.to_csv(os.path.join(PROCESSED_DATA_DIR, "features_train.csv"), index=False)

    test_df = pd.DataFrame(X_test_s, columns=ML_FEATURE_COLUMNS)
    test_df["label_binary"] = y_test_b
    test_df["label_multi"]  = y_test_m
    test_df.to_csv(os.path.join(PROCESSED_DATA_DIR, "features_test.csv"), index=False)

    pd.DataFrame({"label_int": range(len(label_names)), "label_name": label_names}).to_csv(
        os.path.join(PROCESSED_DATA_DIR, "label_names.csv"), index=False)

    # Save artifacts
    joblib.dump(scaler, SCALER_PATH)
    joblib.dump(le, ENCODER_PATH)
    joblib.dump(ML_FEATURE_COLUMNS, FEATURE_COLS_PATH)
    logger.info("Saved scaler, encoder, feature list.")
    logger.info("Preprocessing complete!")

    return {
        "X_train": X_train_s, "X_test": X_test_s,
        "y_train_binary": y_train_b, "y_test_binary": y_test_b,
        "y_train_multi": y_train_m, "y_test_multi": y_test_m,
        "label_names": label_names, "feature_columns": ML_FEATURE_COLUMNS,
        "scaler": scaler, "label_encoder": le,
    }
