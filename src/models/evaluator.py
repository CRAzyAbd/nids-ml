# src/models/evaluator.py
"""
Generates evaluation charts and a final performance report.

Charts produced:
  1. Confusion matrix heatmap (Random Forest)
  2. Feature importance bar chart (top 20)
  3. Anomaly score distribution (Isolation Forest)
  4. ROC curve (binary classification)

All charts saved to data/reports/
"""

import os
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import seaborn as sns

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.utils.logger import setup_logger
from config.settings import LOG_FILE, LOG_LEVEL, REPORTS_DIR

logger = setup_logger(__name__, LOG_FILE, LOG_LEVEL)

PALETTE = {
    "BENIGN":     "#2ecc71",
    "DoS":        "#e74c3c",
    "DDoS":       "#c0392b",
    "PortScan":   "#e67e22",
    "BruteForce": "#9b59b6",
    "WebAttack":  "#3498db",
    "ANOMALY":    "#e74c3c",
    "NORMAL":     "#2ecc71",
}


def plot_confusion_matrix(cm: np.ndarray,
                          label_names: list,
                          filename: str = "04_confusion_matrix.png"):
    """
    Plot a normalized confusion matrix heatmap.

    Normalizing by row (true label) shows RECALL per class —
    what fraction of each attack type was correctly identified.
    This is more informative than raw counts for imbalanced classes.
    """
    os.makedirs(REPORTS_DIR, exist_ok=True)

    # Normalize: each row sums to 1.0
    cm_norm = cm.astype(float) / cm.sum(axis=1, keepdims=True)

    fig, axes = plt.subplots(1, 2, figsize=(16, 6))
    fig.suptitle("Random Forest — Confusion Matrix", fontsize=14, fontweight="bold")

    # Left: raw counts
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                xticklabels=label_names, yticklabels=label_names,
                ax=axes[0], cbar=False)
    axes[0].set_title("Raw Counts")
    axes[0].set_xlabel("Predicted")
    axes[0].set_ylabel("Actual")
    axes[0].tick_params(axis='x', rotation=30)

    # Right: normalized
    sns.heatmap(cm_norm, annot=True, fmt=".2f", cmap="YlOrRd",
                xticklabels=label_names, yticklabels=label_names,
                ax=axes[1], cbar=True,
                vmin=0, vmax=1)
    axes[1].set_title("Normalized (Recall per Class)")
    axes[1].set_xlabel("Predicted")
    axes[1].set_ylabel("Actual")
    axes[1].tick_params(axis='x', rotation=30)

    plt.tight_layout()
    path = os.path.join(REPORTS_DIR, filename)
    plt.savefig(path, dpi=120, bbox_inches="tight")
    plt.close()
    logger.info(f"  Saved confusion matrix → {path}")
    return path


def plot_feature_importance(feature_importances: list,
                            top_n: int = 20,
                            filename: str = "05_feature_importance.png"):
    """
    Horizontal bar chart of top N most important features.

    Feature importance in Random Forest = mean decrease in Gini impurity
    when splitting on that feature, averaged across all trees.
    Higher = the model relies on this feature more to make decisions.
    """
    os.makedirs(REPORTS_DIR, exist_ok=True)

    top = feature_importances[:top_n]
    features = [f for f, _ in top]
    scores   = [s for _, s in top]

    fig, ax = plt.subplots(figsize=(10, 8))
    colors = plt.cm.RdYlGn(np.linspace(0.3, 0.9, len(scores)))[::-1]
    bars = ax.barh(features[::-1], scores[::-1], color=colors[::-1], edgecolor="white")
    ax.set_xlabel("Feature Importance (Mean Decrease in Gini)", fontsize=11)
    ax.set_title(f"Random Forest — Top {top_n} Feature Importances",
                 fontsize=13, fontweight="bold")
    ax.bar_label(bars, labels=[f"{s:.4f}" for s in scores[::-1]],
                 padding=3, fontsize=8)
    ax.set_xlim(0, max(scores) * 1.15)
    plt.tight_layout()

    path = os.path.join(REPORTS_DIR, filename)
    plt.savefig(path, dpi=120, bbox_inches="tight")
    plt.close()
    logger.info(f"  Saved feature importance → {path}")
    return path


def plot_anomaly_scores(scores: np.ndarray,
                        y_binary: np.ndarray,
                        threshold: float,
                        filename: str = "06_anomaly_scores.png"):
    """
    Histogram of Isolation Forest anomaly scores split by true label.

    A good model shows two clearly separated distributions:
      - BENIGN flows: scores clustered toward 0 (harder to isolate)
      - ATTACK flows: scores clustered toward -0.5 (easier to isolate)
    """
    os.makedirs(REPORTS_DIR, exist_ok=True)

    benign_scores = scores[y_binary == 0]
    attack_scores = scores[y_binary == 1]

    fig, ax = plt.subplots(figsize=(10, 5))
    ax.hist(benign_scores, bins=80, alpha=0.6, color="#2ecc71",
            label=f"BENIGN (n={len(benign_scores):,})", density=True)
    ax.hist(attack_scores, bins=80, alpha=0.6, color="#e74c3c",
            label=f"ATTACK (n={len(attack_scores):,})", density=True)
    ax.axvline(threshold, color="black", linestyle="--", linewidth=1.5,
               label=f"Threshold ({threshold:.3f})")
    ax.set_xlabel("Anomaly Score (lower = more anomalous)", fontsize=11)
    ax.set_ylabel("Density", fontsize=11)
    ax.set_title("Isolation Forest — Anomaly Score Distributions",
                 fontsize=13, fontweight="bold")
    ax.legend(fontsize=10)
    plt.tight_layout()

    path = os.path.join(REPORTS_DIR, filename)
    plt.savefig(path, dpi=120)
    plt.close()
    logger.info(f"  Saved anomaly score distribution → {path}")
    return path


def save_training_report(rf_metrics: dict,
                         iso_metrics: dict,
                         label_names: list,
                         filename: str = "training_report.txt"):
    """Save a plain-text summary of all training results."""
    os.makedirs(REPORTS_DIR, exist_ok=True)
    path = os.path.join(REPORTS_DIR, filename)

    lines = [
        "=" * 65,
        "  NIDS — Phase 4 Training Report",
        "=" * 65,
        "",
        "── RANDOM FOREST (Supervised Multiclass) ─────────────────",
        f"  Classes        : {label_names}",
        f"  Accuracy       : {rf_metrics['accuracy']:.4f} ({rf_metrics['accuracy']*100:.2f}%)",
        f"  F1 (macro)     : {rf_metrics['f1_macro']:.4f}",
        f"  F1 (weighted)  : {rf_metrics['f1_weighted']:.4f}",
        "",
        "  Per-class Report:",
        rf_metrics["report"],
        "",
        "── ISOLATION FOREST (Unsupervised Anomaly Detection) ──────",
        f"  Detection Rate : {iso_metrics['detection_rate']:.4f} "
        f"({iso_metrics['detection_rate']*100:.1f}% of attacks caught)",
        f"  False Alarm    : {iso_metrics['false_alarm_rate']:.4f} "
        f"({iso_metrics['false_alarm_rate']*100:.1f}% of benign flagged)",
        f"  Precision      : {iso_metrics['precision']:.4f}",
        f"  TP={iso_metrics['tp']} TN={iso_metrics['tn']} "
        f"FP={iso_metrics['fp']} FN={iso_metrics['fn']}",
        "",
        "=" * 65,
    ]

    with open(path, "w") as f:
        f.write("\n".join(lines))

    logger.info(f"  Training report saved → {path}")
    return path
