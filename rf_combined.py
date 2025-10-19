# Import libraries
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
import os

# Set path
preprocessed_dir = r"C:\Users\sidne\OneDrive\Desktop\Studies\sem 4.2\IS Project\Project\Preprocessed"

# Load UNSW
X_unsw = pd.read_csv(os.path.join(preprocessed_dir, "UNSW_X_dos.csv"))
y_unsw = pd.read_csv(os.path.join(preprocessed_dir, "UNSW_y_dos.csv"))['is_dos']

# Load CIC
X_cic = pd.read_csv(os.path.join(preprocessed_dir, "CIC_X_dos.csv"))
y_cic = pd.read_csv(os.path.join(preprocessed_dir, "CIC_y_dos.csv"))['is_dos']

print(f" Loaded datasets:")
print(f"   UNSW: {X_unsw.shape[0]:,} samples, {X_unsw.shape[1]} features")
print(f"   CIC:  {X_cic.shape[0]:,} samples, {X_cic.shape[1]} features")

# Find & Align Common Features

# Find features present in BOTH datasets
common_features = X_unsw.columns.intersection(X_cic.columns)

print(f" Common features ({len(common_features)}):")
for i, feat in enumerate(common_features, 1):
    print(f"  {i}. {feat}")

# Select only common features
X_unsw_common = X_unsw[common_features]
X_cic_common = X_cic[common_features]

# Combine
X_combined = pd.concat([X_unsw_common, X_cic_common], ignore_index=True)
y_combined = pd.concat([y_unsw, y_cic], ignore_index=True)

print(f"\n Combined dataset: {X_combined.shape[0]:,} samples, {X_combined.shape[1]} features")
print(f"DoS prevalence: {y_combined.mean()*100:.2f}%")

# Train Model
# Split data
X_train, X_test, y_train, y_test = train_test_split(
    X_combined, y_combined,
    test_size=0.2,
    stratify=y_combined,
    random_state=42
)

print(f"SplitOptions:")
print(f"  Train: {X_train.shape[0]:,} samples")
print(f"  Test:  {X_test.shape[0]:,} samples")

# Train
print("\n Training unified Random Forest model...")
rf_combined = RandomForestClassifier(
    n_estimators=100,
    class_weight='balanced',
    random_state=42,
    n_jobs=-1
)
rf_combined.fit(X_train, y_train)
print(" Training complete!")

#Performance Evaluation
# Predict
y_pred = rf_combined.predict(X_test)

# Report
print("===  COMBINED MODEL PERFORMANCE ===")
print(classification_report(y_test, y_pred, target_names=['Benign', 'DoS']))

# Confusion Matrix
plt.figure(figsize=(6, 5))
cm = confusion_matrix(y_test, y_pred)
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
            xticklabels=['Benign', 'DoS'],
            yticklabels=['Benign', 'DoS'])
plt.title('Confusion Matrix (Combined Model)')
plt.ylabel('True Label')
plt.xlabel('Predicted Label')
plt.show()

# Feature Importance Highlight
# Feature importance
importances = pd.Series(rf_combined.feature_importances_, index=common_features)
top_features = importances.sort_values(ascending=False)

plt.figure(figsize=(8, 6))
top_features.plot(kind='barh', color='teal')
plt.title('Top Features in Combined Model')
plt.xlabel('Importance')
plt.gca().invert_yaxis()
plt.tight_layout()
plt.show()

print("Top Features:")
print(top_features)

#Save the model
model_path = os.path.join(preprocessed_dir, "rf_combined_dos.joblib")
joblib.dump(rf_combined, model_path)

print(f"Final model saved successfully!")
print(f"Location: {model_path}")
print(f"Size: {os.path.getsize(model_path) / (1024*1024):.2f} MB")

# Also save feature list for reproducibility
pd.Series(common_features).to_csv(os.path.join(preprocessed_dir, "combined_features.csv"), index=False, header=['feature'])
print(f"Feature list saved to: combined_features.csv")