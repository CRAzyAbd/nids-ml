import os, sys
import pandas as pd
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.data.dataset_loader import load_dataset
from src.data.preprocessor import preprocess
from config.settings import PROCESSED_DATA_DIR

def main():
    print("\nNIDS - Data Preprocessing Pipeline\n" + "="*65)
    df = load_dataset()
    if df.empty:
        print("No data loaded. Check data/raw/MachineLearningCVE/"); sys.exit(1)
    print(f"Loaded {len(df):,} rows")
    result = preprocess(df)
    print("\n" + "="*65)
    print(f"Train: {result['X_train'].shape[0]:,}  Test: {result['X_test'].shape[0]:,}")
    print(f"Features: {result['X_train'].shape[1]}")
    print(f"Classes: {result['label_names']}")
    print(f"\nSaved to: {PROCESSED_DATA_DIR}/")
    print("\nReady for Phase 4!")

if __name__ == "__main__":
    main()
