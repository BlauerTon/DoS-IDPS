import pandas as pd
import os
import numpy as np

# 1. PATHS
data_dir = r"C:\Users\sidne\OneDrive\Desktop\Studies\sem 4.2\IS Project\Project\Data\MachineLearningCVE"
output_dir = r"C:\Users\sidne\OneDrive\Desktop\Studies\sem 4.2\IS Project\Project\Preprocessed"

os.makedirs(output_dir, exist_ok=True)

# 2. FILES & LABELS
files = [
    "Monday-WorkingHours.pcap_ISCX.csv",                      # Benign
    "Wednesday-workingHours.pcap_ISCX.csv",                   # DoS
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",              # Benign 
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"        # DDoS → DoS
]

dos_labels = {
    'DoS Hulk', 'DoS GoldenEye', 'DoS slowloris', 
    'DoS Slowhttptest', 'DDoS'
}

# 3. PROCESS EACH FILE
all_data = []

for file in files:
    print(f" Processing {file}...")
    path = os.path.join(data_dir, file)
    
    # Load and CLEAN COLUMN NAMES (strip whitespace)
    df = pd.read_csv(path, low_memory=False)
    df.columns = df.columns.str.strip()  
    
    print(f"   Raw rows: {len(df):,}")
    
    # Now 'Label' column is clean
    df_filtered = df[
        (df['Label'] == 'BENIGN') | 
        (df['Label'].isin(dos_labels))
    ].copy()
    
    df_filtered['is_dos'] = df_filtered['Label'].apply(lambda x: 1 if x in dos_labels else 0)
    
    print(f"   Kept: {len(df_filtered):,} rows "
          f"({(df_filtered['is_dos'] == 0).sum():,} benign, "
          f"{(df_filtered['is_dos'] == 1).sum():,} DoS)")
    
    all_data.append(df_filtered)

# Combine
full_df = pd.concat(all_data, ignore_index=True)
print(f"\n✅ Total CIC samples: {len(full_df):,}")

# 4. SELECT ALIGNABLE FEATURES

feature_map = {
    'Flow Duration': 'dur',
    'Total Fwd Packets': 'Spkts',
    'Total Backward Packets': 'Dpkts',
    'Total Length of Fwd Packets': 'sbytes',
    'Total Length of Bwd Packets': 'dbytes',
    'Fwd IAT Mean': 'Sintpkt',
    'Bwd IAT Mean': 'Dintpkt',
    'Flow IAT Mean': 'tcprtt',
    'SYN Flag Count': 'syn_flag',
    'RST Flag Count': 'rst_flag',
    'Average Packet Size': 'avg_pkt_size',
    'Fwd PSH Flags': 'fwd_psh',
    'Bwd PSH Flags': 'bwd_psh'
}

available_features = [col for col in feature_map.keys() if col in full_df.columns]
print(f"\n🔍 Available alignable features in CIC: {len(available_features)}")
print(available_features)

X_cic = full_df[available_features].copy()
X_cic.rename(columns=feature_map, inplace=True)

# Clean data
X_cic = X_cic.replace([np.inf, -np.inf], np.nan).fillna(0)
y_cic = full_df['is_dos']

# 5. SAVE
X_cic.to_csv(os.path.join(output_dir, "CIC_X_dos.csv"), index=False)
y_cic.to_csv(os.path.join(output_dir, "CIC_y_dos.csv"), index=False, header=['is_dos'])

print(f"\n Saved CIC_X_dos.csv ({X_cic.shape[0]:,} x {X_cic.shape[1]})")
print(f" Saved CIC_y_dos.csv")

# 6. SUMMARY
print("\n CIC Class Distribution:")
print(f"   Benign: {(y_cic == 0).sum():,} ({100*(y_cic==0).mean():.2f}%)")
print(f"   DoS:    {(y_cic == 1).sum():,} ({100*(y_cic==1).mean():.2f}%)")