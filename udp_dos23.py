import os
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import seaborn as sns
import matplotlib.pyplot as plt
import joblib

#  Configuration 
DATA_PATH = r"C:\Users\sidne\OneDrive\Desktop\Studies\sem 4.2\IS Project\Project\Preprocessed\ciciot2023_udp_flood_dataset.csv"
MODEL_DIR = r"C:\Users\sidne\OneDrive\Desktop\Studies\sem 4.2\IS Project\Project\Models"
os.makedirs(MODEL_DIR, exist_ok=True)
MODEL_PATH = os.path.join(MODEL_DIR, "udp_dos23.joblib")

#  Load Data 
print("Loading dataset...")
df = pd.read_csv(DATA_PATH)
print(f"Loaded {len(df):,} samples.")

#  Prepare Features and Labels 
X = df.drop('Label', axis=1)
y = df['Label']

# Clean infinite values and extreme outliers
print("Cleaning data: replacing inf/-inf and clipping outliers...")
X.replace([np.inf, -np.inf], np.nan, inplace=True)

# Clip to 0.1% and 99.9% percentiles to handle extreme values
for col in X.columns:
    if X[col].isna().all():
        continue
    lower = X[col].quantile(0.001)
    upper = X[col].quantile(0.999)
    X[col] = X[col].clip(lower=lower, upper=upper)

# Impute remaining NaNs with median
if X.isnull().values.any():
    print("Imputing missing values with median...")
    X = X.fillna(X.median())

#  Train-Test Split 
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    stratify=y,
    random_state=42
)
print(f"Train set: {X_train.shape[0]:,} samples")
print(f"Test set:  {X_test.shape[0]:,} samples")

#  Train Model 
print("Training Random Forest classifier...")
rf = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    class_weight='balanced',
    n_jobs=-1
)
rf.fit(X_train, y_train)

#  Evaluate 
y_pred = rf.predict(X_test)

# Accuracy
train_acc = accuracy_score(y_train, rf.predict(X_train))
test_acc = accuracy_score(y_test, y_pred)
print(f"\nTraining Accuracy: {train_acc:.6f}")
print(f"Test Accuracy:     {test_acc:.6f}")
print(f"Accuracy Gap:      {train_acc - test_acc:.6f}")

# Classification report
print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=['Benign', 'DoS-UDP']))

# Confusion matrix
cm = confusion_matrix(y_test, y_pred, labels=['Benign', 'DoS-UDP'])
print("\nConfusion Matrix:")
print(cm)

# Plot and save confusion matrix
plt.figure(figsize=(6, 5))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
            xticklabels=['Benign', 'DoS-UDP'],
            yticklabels=['Benign', 'DoS-UDP'])
plt.title('Confusion Matrix – UDP DoS Detection (CIC-IoT 2023)')
plt.ylabel('True Label')
plt.xlabel('Predicted Label')
plt.tight_layout()
plt.savefig(os.path.join(MODEL_DIR, "confusion_matrix_udp_dos23.png"), dpi=150)

#  Save Model 
joblib.dump(rf, MODEL_PATH)
print(f"\nModel saved to: {MODEL_PATH}")

#  Feature Importance 
print("\nTop 10 Most Important Features:")
importances = pd.Series(rf.feature_importances_, index=X.columns)
top_features = importances.sort_values(ascending=False).head(10)
for i, (feat, imp) in enumerate(top_features.items(), 1):
    print(f"  {i:2d}. {feat:<20} : {imp:.4f}")

print("\nTraining and evaluation completed successfully.")