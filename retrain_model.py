"""
Obsidian Lens — Full Model Retraining Script
Wipes the old model and trains a new one on ALL 8 CICIDS2017 CSV files.
Run with: python retrain_model.py
"""

import os
import sys

# Add project root to path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from ml.model_manager import delete_model, save_model
from ml.real_dataset_loader import load_real_dataset
from ml.classifier import BehavioralClassifier
from ml.preprocessor import Preprocessor

print("=" * 60)
print("  OBSIDIAN LENS — MASTER MODEL RETRAINING")
print("=" * 60)

# Step 1: Delete old model
print("\n[1/4] Wiping previous model...")
if delete_model():
    print("  -> Old model deleted.")
else:
    print("  -> No old model found, starting fresh.")

# Step 2: Load ALL 8 datasets
# We cap at 200,000 rows for balanced training (avoids RAM overflow)
print("\n[2/4] Loading all CICIDS2017 dataset files (~200k rows)...")
df = load_real_dataset(max_rows=200000)

label_counts = df['label'].value_counts()
print(f"\n  Label Distribution:")
for label, count in label_counts.items():
    print(f"    {label:<30} {count:>8,} samples")

# Step 3: Preprocess
print("\n[3/4] Preprocessing features...")
from ml.preprocessor import FEATURE_COLUMNS
preprocessor = Preprocessor()
# fit_transform expects a full DataFrame with 'label' column and returns (X, y)
X, y = preprocessor.fit_transform(df)

print(f"  -> Feature matrix: {X.shape}")
print(f"  -> Classes: {list(set(y))}")

# Step 4: Train
print("\n[4/4] Training Random Forest classifier (this may take 3-5 minutes)...")
classifier = BehavioralClassifier(n_estimators=100)
metrics = classifier.train(X, y)

print(f"\n  TRAINING COMPLETE!")
print(f"  -> Training Accuracy : {metrics['train_accuracy']*100:.2f}%")
print(f"  -> CV Accuracy       : {metrics['cv_mean_accuracy']*100:.2f}% (+/- {metrics['cv_std']*100:.2f}%)")
print(f"  -> Total Samples     : {metrics['n_samples']:,}")
print(f"  -> Classes Learned   : {metrics['n_classes']} ({', '.join(metrics['class_labels'])})")

# Save
print("\n[SAVE] Saving new model to disk...")
save_model(
    classifier,
    preprocessor,
    metadata={
        'dataset': 'CICIDS2017 (All 8 files)',
        'n_samples': metrics['n_samples'],
        'classes': metrics['class_labels'],
        'cv_accuracy': metrics['cv_mean_accuracy'],
    }
)
print("  -> Model saved to models/current/")

print("\n" + "=" * 60)
print("  DONE! Restart app.py to load the new model.")
print("=" * 60)
