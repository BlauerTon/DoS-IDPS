#!/usr/bin/env python3
"""
extract_cic_features.py

Extract engineered features from a single CIC CSV (e.g., Tuesday traffic).
Writes a new file with only the selected features + label.
"""

import os
import pandas as pd
import numpy as np

# === EDIT THIS PATH ===
INPUT_FILE = r"C:\Users\sidne\OneDrive\Desktop\Studies\sem 4.2\IS Project\Project\Data\Tuesday-WorkingHours.pcap_ISCX.csv"
OUT_FILE = os.path.splitext(INPUT_FILE)[0] + "_features.csv"

# Known UDP ports (heuristic)
UDP_PORTS = {53, 123, 161, 162, 69, 500, 33434}

def normalize_cols(df):
    df = df.copy()
    df.columns = (
        df.columns.str.strip()
        .str.lower()
        .str.replace(" ", "_")
        .str.replace("-", "_")
        .str.replace("/", "_")
    )
    return df

def extract_features_from_df(df):
    df = normalize_cols(df)

    get = lambda name: df[name] if name in df.columns else pd.Series([0]*len(df))

    flow_duration = get("flow_duration").astype(float)
    total_fwd = get("total_fwd_packets").astype(float)
    total_bwd = get("total_backward_packets").astype(float)
    total_len_fwd = get("total_length_of_fwd_packets").astype(float)
    total_len_bwd = get("total_length_of_bwd_packets").astype(float)
    fwd_mean = get("fwd_packet_length_mean").astype(float)
    bwd_mean = get("bwd_packet_length_mean").astype(float)
    fwd_std = get("fwd_packet_length_std").astype(float)
    bwd_std = get("bwd_packet_length_std").astype(float)
    dst_port = get("destination_port").fillna(0).astype(float)
    label_raw = get("label").astype(str)

    eps = 1.0
    pps = (total_fwd + total_bwd) / (flow_duration + eps)
    bps = (total_len_fwd + total_len_bwd) / (flow_duration + eps)
    pkt_len_mean = pd.concat([fwd_mean, bwd_mean], axis=1).mean(axis=1)
    pkt_len_std = pd.concat([fwd_std, bwd_std], axis=1).mean(axis=1)
    fwd_pkt_ratio = total_fwd / (total_bwd + 1.0)

    is_udp = dst_port.apply(lambda dp: 1 if int(dp) in UDP_PORTS else 0)

    kb = ["dos", "ddos", "attack", "flood"]
    label_binary = label_raw.str.lower().apply(lambda s: 1 if any(k in s for k in kb) else 0)

    df_out = pd.DataFrame({
        "pps": pps,
        "bps": bps,
        "pkt_len_mean": pkt_len_mean,
        "pkt_len_std": pkt_len_std,
        "fwd_pkt_ratio": fwd_pkt_ratio,
        "is_udp": is_udp,
        "label_binary": label_binary
    }).replace([np.inf, -np.inf], 0).fillna(0)

    return df_out

def main():
    print("Loading:", INPUT_FILE)
    df = pd.read_csv(INPUT_FILE, low_memory=False)
    df_feats = extract_features_from_df(df)
    df_feats.to_csv(OUT_FILE, index=False)
    print("Saved extracted features →", OUT_FILE)
    print("Shape:", df_feats.shape)
    print("Label counts:\n", df_feats["label_binary"].value_counts())

if __name__ == "__main__":
    main()
