import os
import pandas as pd
import numpy as np
from tqdm import tqdm
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.data.feature_alignment import align_cicids_dataframe
from src.utils.logger import setup_logger
from config.settings import (
    LOG_FILE, LOG_LEVEL, RAW_DATA_DIR, CICIDS_FILES,
    MAX_BENIGN_ROWS, MAX_ATTACK_ROWS, RANDOM_STATE,
)

logger = setup_logger(__name__, LOG_FILE, LOG_LEVEL)


def _load_single_file(filepath):
    filename = os.path.basename(filepath)
    logger.info(f"Loading: {filename}")
    chunks = []
    try:
        reader = pd.read_csv(filepath, encoding="latin-1",
                             chunksize=50_000, low_memory=False)
        for chunk in tqdm(reader, desc=f"  {filename}", unit="chunk"):
            chunk = align_cicids_dataframe(chunk)
            chunks.append(chunk)
    except FileNotFoundError:
        logger.error(f"File not found: {filepath}")
        return pd.DataFrame()
    except Exception as e:
        logger.error(f"Error loading {filename}: {e}")
        return pd.DataFrame()
    if not chunks:
        return pd.DataFrame()
    df = pd.concat(chunks, ignore_index=True)
    logger.info(f"  Loaded {len(df):,} rows")
    if "label" in df.columns:
        for label, count in df["label"].value_counts().items():
            logger.info(f"    {label:<20} {count:>8,}")
    return df


def load_dataset(max_benign=MAX_BENIGN_ROWS, max_attack=MAX_ATTACK_ROWS):
    logger.info("=" * 65)
    logger.info("  DATASET LOADER")
    logger.info("=" * 65)
    all_dfs = []
    for filename in CICIDS_FILES:
        filepath = os.path.join(RAW_DATA_DIR, filename)
        if not os.path.exists(filepath):
            logger.warning(f"Skipping (not found): {filename}")
            continue
        df = _load_single_file(filepath)
        if not df.empty:
            all_dfs.append(df)
    if not all_dfs:
        logger.error("No files loaded.")
        return pd.DataFrame()
    combined = pd.concat(all_dfs, ignore_index=True)
    logger.info(f"Total rows before sampling: {len(combined):,}")
    sampled_parts = []
    for label in combined["label"].unique():
        subset = combined[combined["label"] == label]
        if label == "BENIGN" and max_benign and len(subset) > max_benign:
            subset = subset.sample(n=max_benign, random_state=RANDOM_STATE)
            logger.info(f"  BENIGN sampled to {max_benign:,}")
        elif label != "BENIGN" and max_attack and len(subset) > max_attack:
            subset = subset.sample(n=max_attack, random_state=RANDOM_STATE)
            logger.info(f"  {label:<20} sampled to {max_attack:,}")
        else:
            logger.info(f"  {label:<20} kept {len(subset):,}")
        sampled_parts.append(subset)
    combined = pd.concat(sampled_parts, ignore_index=True)
    logger.info(f"Total rows after sampling: {len(combined):,}")
    return combined
