import os, sys, warnings
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns
warnings.filterwarnings("ignore")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.data.dataset_loader import load_dataset
from src.data.feature_alignment import ML_FEATURE_COLUMNS, BINARY_LABEL_MAP
from config.settings import REPORTS_DIR

os.makedirs(REPORTS_DIR, exist_ok=True)

PALETTE = {
    "BENIGN":"#2ecc71","DoS":"#e74c3c","DDoS":"#c0392b",
    "PortScan":"#e67e22","BruteForce":"#9b59b6","WebAttack":"#3498db",
    "Bot":"#1abc9c","Infiltration":"#f39c12","UNKNOWN":"#95a5a6",
}

def run_eda():
    lines = []
    def log(m=""):
        print(m); lines.append(str(m))

    log("NIDS - EDA"); log("=" * 65)
    df = load_dataset()
    if df.empty:
        print("No data loaded."); return
    log(f"Shape: {df.shape[0]:,} rows x {df.shape[1]} cols")
    total = len(df)

    log("\n1. Class Distribution")
    cc = df["label"].value_counts()
    for lbl, cnt in cc.items():
        pct = cnt/total*100
        log(f"  {lbl:<20} {cnt:>8,}  {pct:5.1f}%  {'█'*int(pct/2)}")

    fig, ax = plt.subplots(figsize=(10,5))
    colors = [PALETTE.get(l,"#95a5a6") for l in cc.index]
    bars = ax.barh(cc.index, cc.values, color=colors, edgecolor="white")
    ax.set_xlabel("Flows"); ax.set_title("Class Distribution", fontweight="bold")
    ax.bar_label(bars, labels=[f"{v:,}" for v in cc.values], padding=3, fontsize=9)
    plt.tight_layout()
    p = os.path.join(REPORTS_DIR, "01_class_distribution.png")
    plt.savefig(p, dpi=120); plt.close(); log(f"  Chart → {p}")

    log("\n2. Missing & Infinity Values")
    fc = [c for c in ML_FEATURE_COLUMNS if c in df.columns]
    inf_n = ((df[fc]==np.inf)|(df[fc]==-np.inf)).sum().sum()
    nan_n = df[fc].isna().sum().sum()
    log(f"  Inf: {int(inf_n):,}  NaN: {int(nan_n):,}")

    log("\n3. Correlation Heatmap")
    corr = df[fc].replace([np.inf,-np.inf],np.nan).dropna().corr()
    fig, ax = plt.subplots(figsize=(16,14))
    mask = np.triu(np.ones_like(corr,dtype=bool))
    sns.heatmap(corr,mask=mask,cmap="coolwarm",center=0,annot=False,linewidths=0.3,ax=ax)
    ax.set_title("Feature Correlation Matrix", fontweight="bold")
    plt.tight_layout()
    p = os.path.join(REPORTS_DIR, "02_correlation_heatmap.png")
    plt.savefig(p, dpi=100); plt.close(); log(f"  Chart → {p}")

    log("\n4. Feature Distributions")
    plot_feats = [
        ("bytes_per_sec","Bytes/sec",True),
        ("flow_iat_mean","Flow IAT Mean",True),
        ("syn_count","SYN Count",False),
        ("fwd_pkt_len_mean","Fwd Pkt Len Mean",False),
    ]
    fig, axes = plt.subplots(2,2,figsize=(14,10))
    fig.suptitle("Feature Distributions by Class", fontweight="bold")
    lp = df["label"].unique()
    clrs = [PALETTE.get(l,"#95a5a6") for l in lp]
    for ax,(feat,title,ls) in zip(axes.flat, plot_feats):
        if feat not in df.columns:
            ax.set_title(f"{title} (N/A)"); continue
        s = df[feat].replace([np.inf,-np.inf],np.nan).clip(upper=df[feat].quantile(0.99))
        for lbl,clr in zip(lp,clrs):
            sub = s[df["label"]==lbl].dropna()
            if len(sub): ax.hist(sub,bins=40,alpha=0.55,label=lbl,color=clr,density=True)
        ax.set_title(title); ax.set_xlabel(feat); ax.set_ylabel("Density")
        if ls: ax.set_xscale("log")
        ax.legend(fontsize=7)
    plt.tight_layout()
    p = os.path.join(REPORTS_DIR, "03_feature_distributions.png")
    plt.savefig(p, dpi=120); plt.close(); log(f"  Chart → {p}")

    log("\n5. Binary Balance")
    df["lb"] = df["label"].map(BINARY_LABEL_MAP).fillna(1).astype(int)
    b = (df["lb"]==0).sum(); a = (df["lb"]==1).sum()
    log(f"  BENIGN: {b:,} ({b/total*100:.1f}%)  ATTACK: {a:,} ({a/total*100:.1f}%)")

    rp = os.path.join(REPORTS_DIR,"eda_report.txt")
    with open(rp,"w") as f: f.write("\n".join(lines))
    print(f"\nEDA COMPLETE\nReport → {rp}\nCharts → {REPORTS_DIR}/\n")

if __name__ == "__main__":
    run_eda()
