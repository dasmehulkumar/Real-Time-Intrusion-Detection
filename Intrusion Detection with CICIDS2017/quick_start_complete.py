# quick_start_complete.py
# Quick Start Training Script for Intrusion Detection System

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
import sys
import os

from ids_system_complete import IntrusionDetectionSystem


def create_sample_cicids2017_dataset(n_samples=10000):
    """
    Create a sample dataset mimicking CICIDS2017 structure
    """
    print(f"\nGenerating sample CICIDS2017-style dataset ({n_samples} samples)...")

    np.random.seed(42)

    # 70% benign, 30% attack
    n_benign = int(n_samples * 0.7)
    n_attack = n_samples - n_benign

    print(f"  - Benign traffic: {n_benign} samples")
    print(f"  - Attack traffic: {n_attack} samples")

    # BENIGN traffic features
    benign_data = {
        'Flow Duration': np.random.normal(50000, 20000, n_benign).clip(0),
        'Total Fwd Packets': np.random.randint(1, 50, n_benign),
        'Total Backward Packets': np.random.randint(1, 50, n_benign),
        'Fwd Packet Length Max': np.random.randint(100, 1500, n_benign),
        'Fwd Packet Length Min': np.random.randint(0, 100, n_benign),
        'Fwd Packet Length Mean': np.random.normal(500, 200, n_benign).clip(0, 1500),
        'Bwd Packet Length Max': np.random.randint(100, 1500, n_benign),
        'Bwd Packet Length Min': np.random.randint(0, 100, n_benign),
        'Flow Bytes/s': np.random.normal(10000, 5000, n_benign).clip(0),
        'Flow Packets/s': np.random.normal(10, 5, n_benign).clip(0),
        'Fwd IAT Mean': np.random.normal(1000, 500, n_benign).clip(0),
        'Fwd IAT Max': np.random.normal(2000, 1000, n_benign).clip(0),
        'Bwd IAT Mean': np.random.normal(1000, 500, n_benign).clip(0),
        'Bwd IAT Max': np.random.normal(2000, 1000, n_benign).clip(0),
        'PSH Flag Count': np.random.randint(0, 3, n_benign),
        'ACK Flag Count': np.random.randint(0, 50, n_benign),
        'Down_Up Ratio': np.random.uniform(0, 10, n_benign),
        'Avg Packet Size': np.random.normal(500, 200, n_benign).clip(20, 1500),
        'Fwd Segment Size Avg': np.random.normal(500, 200, n_benign).clip(0, 1500),
        'Subflow Fwd Bytes': np.random.normal(25000, 10000, n_benign).clip(0),
        'Label': ['BENIGN'] * n_benign
    }

    # ATTACK traffic features
    attack_types = ['DoS', 'DDoS', 'PortScan', 'BruteForce']
    attack_data = {
        'Flow Duration': np.random.normal(100000, 50000, n_attack).clip(0),
        'Total Fwd Packets': np.random.randint(50, 500, n_attack),
        'Total Backward Packets': np.random.randint(0, 10, n_attack),
        'Fwd Packet Length Max': np.random.randint(50, 1500, n_attack),
        'Fwd Packet Length Min': np.random.randint(0, 50, n_attack),
        'Fwd Packet Length Mean': np.random.normal(400, 300, n_attack).clip(0, 1500),
        'Bwd Packet Length Max': np.random.randint(0, 500, n_attack),
        'Bwd Packet Length Min': np.random.randint(0, 50, n_attack),
        'Flow Bytes/s': np.random.normal(50000, 20000, n_attack).clip(0),
        'Flow Packets/s': np.random.normal(50, 20, n_attack).clip(0),
        'Fwd IAT Mean': np.random.normal(100, 50, n_attack).clip(0),
        'Fwd IAT Max': np.random.normal(500, 200, n_attack).clip(0),
        'Bwd IAT Mean': np.random.normal(5000, 2000, n_attack).clip(0),
        'Bwd IAT Max': np.random.normal(10000, 3000, n_attack).clip(0),
        'PSH Flag Count': np.random.randint(0, 10, n_attack),
        'ACK Flag Count': np.random.randint(0, 500, n_attack),
        'Down_Up Ratio': np.random.uniform(0, 50, n_attack),
        'Avg Packet Size': np.random.normal(300, 250, n_attack).clip(20, 1500),
        'Fwd Segment Size Avg': np.random.normal(300, 250, n_attack).clip(0, 1500),
        'Subflow Fwd Bytes': np.random.normal(50000, 25000, n_attack).clip(0),
        'Label': np.random.choice(attack_types, n_attack)
    }

    df_benign = pd.DataFrame(benign_data)
    df_attack = pd.DataFrame(attack_data)

    df = pd.concat([df_benign, df_attack], ignore_index=True)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    print("✓ Dataset generated successfully")
    return df


def train_ids_model(use_real_dataset=False, dataset_path=None):
    print("\n" + "="*70)
    print(" "*15 + "INTRUSION DETECTION SYSTEM")
    print(" "*20 + "Training Module")
    print("="*70)

    # Load or create dataset
    if use_real_dataset and dataset_path:
        print(f"\nLoading CICIDS2017 dataset from: {dataset_path}")
        try:
            df = pd.read_csv(dataset_path)
            print(f"✓ Dataset loaded: {len(df)} samples")
        except Exception as e:
            print(f"✗ Error loading dataset: {str(e)}")
            print("Falling back to sample dataset...")
            df = create_sample_cicids2017_dataset()
    else:
        df = create_sample_cicids2017_dataset()

    print("\n" + "-"*70)
    print("DATASET INFORMATION")
    print("-"*70)
    print(f"Total samples: {len(df)}")
    print(f"\nLabel distribution:")
    for label, count in df['Label'].value_counts().items():
        percentage = (count / len(df)) * 100
        print(f"  {label:15s}: {count:6d} ({percentage:5.2f}%)")
    print(f"\nFeatures: {len(df.columns) - 1}")

    ids = IntrusionDetectionSystem()

    X, y = ids.prepare_data(df)

    print("\n" + "-"*70)
    print("DATA SPLITTING")
    print("-"*70)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )
    print(f"Training set: {len(X_train):,} samples (70%)")
    print(f"Test set:     {len(X_test):,} samples (30%)")

    print("\n" + "-"*70)
    print("MODEL TRAINING")
    print("-"*70)
    ids.train_model(X_train, y_train)

    print("\n" + "-"*70)
    print("MODEL EVALUATION")
    print("-"*70)
    accuracy, _ = ids.evaluate_model(X_test, y_test)

    print("\n" + "-"*70)
    print("MODEL SAVING")
    print("-"*70)
    model_filename = 'ids_model.pkl'
    ids.save_model(model_filename)

    file_size = os.path.getsize(model_filename) / (1024 * 1024)
    print(f"✓ Model size: {file_size:.2f} MB")

    print("\n" + "="*70)
    print(" "*20 + "TRAINING COMPLETED")
    print("="*70)
    print(f"\n✓ Model accuracy: {accuracy*100:.2f}%")
    print(f"✓ Model saved: {model_filename}")
    print("\nNext steps:")
    print("  1. Run the web interface: python app.py")
    print("  2. Open browser: http://localhost:5000")
    print("="*70 + "\n")

    return ids


def main():
    use_real = False
    dataset_path = None

    if len(sys.argv) > 1:
        dataset_path = sys.argv[1]
        if os.path.exists(dataset_path):
            use_real = True
            print(f"Using real dataset: {dataset_path}")
        else:
            print(f"Warning: Dataset not found at {dataset_path}")
            print("Using sample dataset instead...")

    train_ids_model(use_real_dataset=use_real, dataset_path=dataset_path)


if __name__ == "__main__":
    main()
