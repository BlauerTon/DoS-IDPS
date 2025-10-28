import os
import pandas as pd
import numpy as np

#  Paths 
base_data_dir = r"C:\Users\sidne\OneDrive\Desktop\Studies\sem 4.2\IS Project\Project\Data\CICIoT2023"
benign_dir = os.path.join(base_data_dir, "Benign")
flood_dir = os.path.join(base_data_dir, "Flood")
output_dir = r"C:\Users\sidne\OneDrive\Desktop\Studies\sem 4.2\IS Project\Project\Preprocessed"
os.makedirs(output_dir, exist_ok=True)

#  Feature selection (based on analysis) 
USE_MINIMAL_FEATURES = False

if USE_MINIMAL_FEATURES:
    selected_features = [
        'Protocol Type', 'Rate', 'IAT',
        'Min', 'Max', 'Std', 'Variance',
        'Tot size', 'Number',
        'TCP', 'UDP'
    ]
else:
    selected_features = None  # Will be set after loading first file

#  Load Benign Files 
print("Loading Benign files...")
benign_dfs = []
for i in range(4):  # BenignTraffic0 to BenignTraffic3
    file_path = os.path.join(benign_dir, f"BenignTraffic{i}.pcap.csv")
    if os.path.exists(file_path):
        df = pd.read_csv(file_path, low_memory=False)
        df['Label'] = 'Benign'
        benign_dfs.append(df)
        print(f"   Loaded: {file_path} (rows: {len(df)})")
    else:
        print(f"    File not found: {file_path}")

#  Load Flood Files 
print("\n Loading DoS-UDP Flood files...")
flood_dfs = []
for i in range(17):  # DoS-UDP_Flood0 to DoS-UDP_Flood16
    file_path = os.path.join(flood_dir, f"DoS-UDP_Flood{i}.pcap.csv")
    if os.path.exists(file_path):
        df = pd.read_csv(file_path, low_memory=False)
        df['Label'] = 'DoS-UDP'
        flood_dfs.append(df)
        print(f"   Loaded: {file_path} (rows: {len(df)})")
    else:
        print(f"    File not found: {file_path}")

#  Combine 
if not benign_dfs or not flood_dfs:
    raise FileNotFoundError("Missing benign or flood files. Check paths and filenames.")

all_dfs = benign_dfs + flood_dfs
full_df = pd.concat(all_dfs, ignore_index=True)
print(f"\n Combined dataset shape: {full_df.shape}")

#  Set feature list if using all columns 
if selected_features is None:
    # Exclude 'Label' from features
    selected_features = [col for col in full_df.columns if col != 'Label']

#  Ensure only selected features + Label are kept 
final_columns = selected_features + ['Label']
missing_cols = set(selected_features) - set(full_df.columns)
if missing_cols:
    raise ValueError(f"Missing expected features: {missing_cols}")

full_df = full_df[final_columns]

#   data cleaning 
for col in selected_features:
    if full_df[col].dtype == 'object':
        full_df[col] = pd.to_numeric(full_df[col], errors='coerce')

# Handle any remaining NaN 
nan_count = full_df[selected_features].isnull().sum().sum()
if nan_count > 0:
    print(f"  Found {nan_count} NaN values. Filling with median per column...")
    for col in selected_features:
        if full_df[col].isnull().any():
            full_df[col].fillna(full_df[col].median(), inplace=True)

#  Final stats 
print(f"\n Final dataset stats:")
print(f" - Total rows: {len(full_df):,}")
print(f" - Features: {len(selected_features)}")
print(f" - Benign samples: {len(full_df[full_df['Label'] == 'Benign']):,}")
print(f" - DoS-UDP samples: {len(full_df[full_df['Label'] == 'DoS-UDP']):,}")

#  Save 
output_path = os.path.join(output_dir, "ciciot2023_udp_flood_dataset.csv")
full_df.to_csv(output_path, index=False)
print(f"\n Dataset saved to:\n{output_path}")

print("\n Preprocessing complete")