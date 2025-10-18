import pandas as pd
import numpy as np
import os

# Configuration
INPUT_PATH = r"C:\Users\sidne\OneDrive\Desktop\Studies\sem 4.2\IS Project\Project\Data\TrafficLabelling\Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
OUTPUT_DIR = r"C:\Users\sidne\OneDrive\Desktop\Studies\sem 4.2\IS Project\Project\Preprocessed"

# Ensure output directory exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Define output paths
OUTPUT_CSV = os.path.join(OUTPUT_DIR, "udp_flood_preprocessed.csv")
OUTPUT_GZ = os.path.join(OUTPUT_DIR, "udp_flood_preprocessed.csv.gz")

# Step 1: Load the dataset
print("Loading dataset...")
df = pd.read_csv(INPUT_PATH, low_memory=False)

# Fix column names 
df.columns = df.columns.str.strip()
print(f"Original shape: {df.shape}")

# Step 2: Filter for UDP (Protocol == 17)
if 'Protocol' not in df.columns:
    raise ValueError("'Protocol' column is missing!")

df_udp = df[df['Protocol'] == 17].copy()
print(f"After filtering UDP (Protocol=17): {df_udp.shape[0]} flows")

# Step 3: Define selected features + label
selected_features = [
    'Destination Port',
    'Flow Duration',
    'Total Fwd Packets',
    'Total Backward Packets',
    'Total Length of Fwd Packets',
    'Flow Packets/s',
    'Flow Bytes/s',
    'Average Packet Size',
    'Min Packet Length',
    'Max Packet Length',
    'Packet Length Std',
    'Flow IAT Mean',
    'Fwd IAT Mean',
    'Fwd IAT Std',
    'Active Mean',
    'Idle Mean'
]

columns_needed = selected_features + ['Label']

# Validate columns
missing_cols = [col for col in columns_needed if col not in df_udp.columns]
if missing_cols:
    raise ValueError(f"Missing columns in dataset: {missing_cols}")

df_clean = df_udp[columns_needed].copy()

# Step 4: Clean the data
print("Cleaning data...")
df_clean.replace([np.inf, -np.inf], np.nan, inplace=True)

# Encode label: 'DDoS' → 1, else → 0
df_clean['Label'] = df_clean['Label'].apply(lambda x: 1 if str(x).strip().lower() == 'ddos' else 0)

# Drop rows with NaN
initial_rows = len(df_clean)
df_clean.dropna(inplace=True)
final_rows = len(df_clean)
print(f"Dropped {initial_rows - final_rows} rows with missing/infinite values.")

# Reduce memory usage
for col in selected_features:
    df_clean[col] = pd.to_numeric(df_clean[col], errors='coerce').astype('float32')
df_clean['Label'] = df_clean['Label'].astype('int8')

# Step 5: Save BOTH formats
print(f"Saving preprocessed UDP dataset as CSV: {OUTPUT_CSV}")
df_clean.to_csv(OUTPUT_CSV, index=False)

print(f"Saving preprocessed UDP dataset as GZ: {OUTPUT_GZ}")
df_clean.to_csv(OUTPUT_GZ, index=False, compression='gzip')

# Final report
print(f"\nPreprocessing complete!")
print(f"Final shape: {df_clean.shape}")
print(f"Class distribution:\n{df_clean['Label'].value_counts()}")
print(f"\nFiles saved to: {OUTPUT_DIR}")