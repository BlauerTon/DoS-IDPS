import pandas as pd
import os
import numpy as np

# 1. CONFIGURATION
data_dir = r"C:\Users\sidne\OneDrive\Desktop\Studies\sem 4.2\IS Project\Project\Data\UNSW-NB15"
output_dir = r"C:\Users\sidne\OneDrive\Desktop\Studies\sem 4.2\IS Project\Project\Preprocessed"

os.makedirs(output_dir, exist_ok=True)

unsw_columns = [
    'srcip', 'sport', 'dstip', 'dport', 'proto', 'state', 'dur', 'sbytes', 'dbytes', 'sttl',
    'dttl', 'sloss', 'dloss', 'service', 'Sload', 'Dload', 'Spkts', 'Dpkts', 'swin', 'dwin',
    'stcpb', 'dtcpb', 'smeansz', 'dmeansz', 'trans_depth', 'res_bdy_len', 'Sjit', 'Djit',
    'Stime', 'Ltime', 'Sintpkt', 'Dintpkt', 'tcprtt', 'synack', 'ackdat', 'is_sm_ips_ports',
    'ct_state_ttl', 'ct_flw_http_mthd', 'is_ftp_login', 'ct_ftp_cmd', 'ct_srv_src', 'ct_srv_dst',
    'ct_dst_ltm', 'ct_src_ltm', 'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm',
    'attack_cat', 'Label'
]

files = [
    "UNSW-NB15_1.csv",
    "UNSW-NB15_2.csv",
    "UNSW-NB15_3.csv",
    "UNSW-NB15_4.csv"
]

dos_files = {"UNSW-NB15_2.csv", "UNSW-NB15_4.csv"}

# 2. LOAD AND FILTER DATA
dataframes = []

for file in files:
    print(f"Processing {file}...")
    path = os.path.join(data_dir, file)
    df = pd.read_csv(path, header=None, names=unsw_columns, low_memory=False)
    
    benign = df[df['Label'] == 0].copy()
    if file in dos_files:
        dos_attacks = df[df['Label'] == 1].copy()
        combined = pd.concat([benign, dos_attacks], ignore_index=True)
    else:
        combined = benign
    
    print(f"  Kept {len(combined)} rows ({len(benign)} benign", end="")
    if file in dos_files:
        print(f", {len(dos_attacks)} DoS)")
    else:
        print(")")
    
    dataframes.append(combined)

full_df = pd.concat(dataframes, ignore_index=True)
print(f"\nTotal rows after filtering: {len(full_df)}")

# 3. CREATE BINARY LABEL
full_df['is_dos'] = full_df['Label'].astype(int)

# 
# 4. SELECT FEATURES FOR DoS DETECTION
features_to_drop = [
    'srcip', 'sport', 'dstip', 'dport',
    'service', 'state',
    'Stime', 'Ltime',
    'trans_depth', 'res_bdy_len',
    'is_ftp_login', 'ct_ftp_cmd',
    'ct_flw_http_mthd',
    'attack_cat',
    'proto'  # all 0 in dataset
]

X = full_df.drop(columns=features_to_drop + ['Label', 'is_dos'], errors='ignore')
X = X.apply(pd.to_numeric, errors='coerce')
X = X.replace([np.inf, -np.inf], np.nan).fillna(0)
y = full_df['is_dos']

print(f"\nFinal feature set: {X.shape[1]} features")
print("Features:", list(X.columns))

# 5. SAVE PROCESSED DATA
X.to_csv(os.path.join(output_dir, "UNSW_X_dos.csv"), index=False)
y.to_csv(os.path.join(output_dir, "UNSW_y_dos.csv"), index=False, header=['is_dos'])
print(f"\nProcessed data saved to: {output_dir}")

# 6. QUICK STATS
print("\n=== CLASS DISTRIBUTION ===")
print(f"Benign (0): {sum(y == 0)}")
print(f"DoS    (1): {sum(y == 1)}")
print(f"Percentage DoS: {100 * y.mean():.2f}%")