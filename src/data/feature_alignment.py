CICIDS_RENAME_MAP = {
    "flow duration":            "duration",
    "total fwd packets":        "total_fwd_packets",
    "total backward packets":   "total_bwd_packets",
    "total length of fwd packets": "total_fwd_bytes",
    "total length of bwd packets": "total_bwd_bytes",
    "fwd packet length mean":   "fwd_pkt_len_mean",
    "fwd packet length std":    "fwd_pkt_len_std",
    "fwd packet length max":    "fwd_pkt_len_max",
    "fwd packet length min":    "fwd_pkt_len_min",
    "bwd packet length mean":   "bwd_pkt_len_mean",
    "bwd packet length std":    "bwd_pkt_len_std",
    "bwd packet length max":    "bwd_pkt_len_max",
    "bwd packet length min":    "bwd_pkt_len_min",
    "max packet length":        "max_pkt_len",
    "min packet length":        "min_pkt_len",
    "packet length mean":       "avg_pkt_len",
    "packet length std":        "std_pkt_len",
    "average packet size":      "avg_pkt_size",
    "flow bytes/s":             "bytes_per_sec",
    "flow packets/s":           "pkts_per_sec",
    "fwd packets/s":            "fwd_pkts_per_sec",
    "bwd packets/s":            "bwd_pkts_per_sec",
    "flow iat mean":            "flow_iat_mean",
    "flow iat std":             "flow_iat_std",
    "flow iat max":             "flow_iat_max",
    "flow iat min":             "flow_iat_min",
    "fwd iat total":            "fwd_iat_total",
    "fwd iat mean":             "fwd_iat_mean",
    "fwd iat std":              "fwd_iat_std",
    "fwd iat max":              "fwd_iat_max",
    "fwd iat min":              "fwd_iat_min",
    "bwd iat total":            "bwd_iat_total",
    "bwd iat mean":             "bwd_iat_mean",
    "bwd iat std":              "bwd_iat_std",
    "bwd iat max":              "bwd_iat_max",
    "bwd iat min":              "bwd_iat_min",
    "fin flag count":           "fin_count",
    "syn flag count":           "syn_count",
    "rst flag count":           "rst_count",
    "psh flag count":           "psh_count",
    "ack flag count":           "ack_count",
    "urg flag count":           "urg_count",
    "cwe flag count":           "cwe_count",
    "ece flag count":           "ece_count",
    "fwd psh flags":            "fwd_psh_flags",
    "bwd psh flags":            "bwd_psh_flags",
    "fwd urg flags":            "fwd_urg_flags",
    "bwd urg flags":            "bwd_urg_flags",
    "down/up ratio":            "bwd_fwd_byte_ratio",
    "init_win_bytes_forward":   "init_win_fwd",
    "init_win_bytes_backward":  "init_win_bwd",
    "act_data_pkt_fwd":         "act_data_pkt_fwd",
    "min_seg_size_forward":     "min_seg_size_fwd",
    "active mean":              "active_mean",
    "active std":               "active_std",
    "active max":               "active_max",
    "active min":               "active_min",
    "idle mean":                "idle_mean",
    "idle std":                 "idle_std",
    "idle max":                 "idle_max",
    "idle min":                 "idle_min",
    "label":                    "label",
}

ML_FEATURE_COLUMNS = [
    "duration",
    "total_fwd_packets", "total_bwd_packets",
    "total_fwd_bytes", "total_bwd_bytes",
    "fwd_pkt_len_mean", "fwd_pkt_len_std", "fwd_pkt_len_max", "fwd_pkt_len_min",
    "bwd_pkt_len_mean", "bwd_pkt_len_std", "bwd_pkt_len_max", "bwd_pkt_len_min",
    "avg_pkt_len", "std_pkt_len",
    "bytes_per_sec", "pkts_per_sec",
    "flow_iat_mean", "flow_iat_std", "flow_iat_max", "flow_iat_min",
    "fwd_iat_mean", "fwd_iat_std", "fwd_iat_max", "fwd_iat_min",
    "bwd_iat_mean", "bwd_iat_std", "bwd_iat_max", "bwd_iat_min",
    "fin_count", "syn_count", "rst_count", "psh_count", "ack_count", "urg_count",
    "bwd_fwd_byte_ratio",
]

LIVE_TO_ML_MAP = {f: f for f in ML_FEATURE_COLUMNS}

MICROSECOND_COLUMNS = [
    "duration",
    "flow_iat_mean", "flow_iat_std", "flow_iat_max", "flow_iat_min",
    "fwd_iat_mean", "fwd_iat_std", "fwd_iat_max", "fwd_iat_min", "fwd_iat_total",
    "bwd_iat_mean", "bwd_iat_std", "bwd_iat_max", "bwd_iat_min", "bwd_iat_total",
    "active_mean", "active_std", "active_max", "active_min",
    "idle_mean", "idle_std", "idle_max", "idle_min",
]

LABEL_NORMALIZATION = {
    "benign":                        "BENIGN",
    "dos hulk":                      "DoS",
    "dos goldeneye":                 "DoS",
    "dos slowhttptest":              "DoS",
    "dos slowloris":                 "DoS",
    "heartbleed":                    "DoS",
    "ddos":                          "DDoS",
    "portscan":                      "PortScan",
    "ftp-patator":                   "BruteForce",
    "ssh-patator":                   "BruteForce",
    "web attack \x96 brute force":  "WebAttack",
    "web attack \x96 xss":          "WebAttack",
    "web attack \x96 sql injection":"WebAttack",
    "web attack - brute force":      "WebAttack",
    "web attack - xss":              "WebAttack",
    "web attack - sql injection":    "WebAttack",
    "web attack- brute force":       "WebAttack",
    "web attack- xss":               "WebAttack",
    "web attack- sql injection":     "WebAttack",
    "web attack – brute force": "WebAttack",
    "web attack – xss":         "WebAttack",
    "web attack – sql injection":"WebAttack",
    "bot":                           "Bot",
    "infiltration":                  "Infiltration",
}

BINARY_LABEL_MAP = {
    "BENIGN": 0, "DoS": 1, "DDoS": 1, "PortScan": 1,
    "BruteForce": 1, "WebAttack": 1, "Bot": 1, "Infiltration": 1,
}

ATTACK_CLASSES = ["DoS","DDoS","PortScan","BruteForce","WebAttack","Bot","Infiltration"]


def align_cicids_dataframe(df):
    import pandas as pd
    df.columns = [c.strip().lower() for c in df.columns]
    rename_targets = {k: v for k, v in CICIDS_RENAME_MAP.items() if k in df.columns}
    df = df.rename(columns=rename_targets)
    for col in MICROSECOND_COLUMNS:
        if col in df.columns:
            df[col] = df[col] / 1_000_000.0
    if "label" in df.columns:
        df["label"] = (
            df["label"].str.strip().str.lower()
            .map(LABEL_NORMALIZATION)
            .fillna("UNKNOWN")
        )
    return df


def align_live_features(feature_dict):
    aligned = {}
    for ml_col in ML_FEATURE_COLUMNS:
        live_col = LIVE_TO_ML_MAP.get(ml_col, ml_col)
        aligned[ml_col] = float(feature_dict.get(live_col, 0.0))
    return aligned
