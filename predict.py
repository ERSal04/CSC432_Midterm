"""
Network Traffic Anomaly Detection - CLI Prediction Tool
CSC432 Midterm Project | Elijah Salgado

Usage:
    python predict.py --csv <path_to_csv> --model <rf|svm>

Examples:
    python predict.py --csv traffic_data.csv --model rf
    python predict.py --csv traffic_data.csv --model svm
    python predict.py --csv traffic_data.csv --model rf --output results.csv
"""

import argparse
import sys
import os
import joblib
import pandas as pd
import numpy as np

# ── The 15 features the models were trained on ──────────────────────────────
FEATURES = [
    'Flow Bytes/s',
    'Flow Packets/s',
    'Fwd Packet Length Max',
    'Fwd Packet Length Mean',
    'Bwd Packet Length Max',
    'Bwd Packet Length Mean',
    'Flow IAT Mean',
    'Flow IAT Std',
    'SYN Flag Count',
    'RST Flag Count',
    'PSH Flag Count',
    'Flow Duration',
    'Total Fwd Packets',
    'Active Mean',
    'Init_Win_bytes_forward',
]

BANNER = """
╔══════════════════════════════════════════════════════════╗
║       Network Traffic Anomaly Detection Tool             ║
║       CSC432 Midterm — Elijah Salgado                    ║
╚══════════════════════════════════════════════════════════╝
"""


def load_model(model_choice, model_dir):
    """Load the chosen model and shared scaler from disk."""
    model_path = os.path.join(model_dir, f"{'random_forest' if model_choice == 'rf' else 'svm'}_model.pkl")
    scaler_path = os.path.join(model_dir, "scaler.pkl")

    if not os.path.exists(model_path):
        print(f"[ERROR] Model file not found: {model_path}")
        print(f"        Make sure your .pkl files are in: {model_dir}")
        sys.exit(1)

    if not os.path.exists(scaler_path):
        print(f"[ERROR] Scaler file not found: {scaler_path}")
        print(f"        Make sure scaler.pkl is in: {model_dir}")
        sys.exit(1)

    print(f"[INFO]  Loading {'Random Forest' if model_choice == 'rf' else 'SVM'} model...")
    model = joblib.load(model_path)
    scaler = joblib.load(scaler_path)
    print("[INFO]  Model and scaler loaded successfully.")
    return model, scaler


def load_csv(csv_path):
    """Load and validate the input CSV file."""
    if not os.path.exists(csv_path):
        print(f"[ERROR] CSV file not found: {csv_path}")
        sys.exit(1)

    print(f"[INFO]  Loading CSV: {csv_path}")
    df = pd.read_csv(csv_path)

    # Strip whitespace from column names (CICIDS2017 has leading spaces)
    df.columns = df.columns.str.strip()

    print(f"[INFO]  Loaded {len(df):,} rows and {len(df.columns)} columns.")
    return df


def validate_features(df):
    """Check that all required features are present in the CSV."""
    missing = [f for f in FEATURES if f not in df.columns]
    if missing:
        print("\n[ERROR] The following required features are missing from your CSV:")
        for f in missing:
            print(f"        - {f}")
        print("\n        Required features:")
        for f in FEATURES:
            print(f"        - {f}")
        sys.exit(1)
    print(f"[INFO]  All 15 required features found.")


def preprocess(df, scaler):
    """Extract features, clean data, and scale."""
    X = df[FEATURES].copy()

    # Replace infinite values with NaN then drop
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    bad_rows = X.isnull().any(axis=1).sum()
    if bad_rows > 0:
        print(f"[WARN]  Dropping {bad_rows:,} rows with NaN or infinite values.")
        X = X.dropna()

    # Scale using the saved scaler
    X_scaled = scaler.transform(X)
    return X_scaled, X.index  # return index so we can align predictions


def run_predictions(model, X_scaled):
    """Run predictions and return labels."""
    print("[INFO]  Running predictions...")
    preds = model.predict(X_scaled)
    labels = ['ATTACK' if p == 1 else 'BENIGN' for p in preds]
    return preds, labels


def print_summary(labels):
    """Print a summary of prediction results."""
    total = len(labels)
    attacks = labels.count('ATTACK')
    benign = labels.count('BENIGN')
    attack_pct = (attacks / total * 100) if total > 0 else 0

    print("\n" + "─" * 50)
    print("  PREDICTION SUMMARY")
    print("─" * 50)
    print(f"  Total flows classified : {total:>10,}")
    print(f"  BENIGN                 : {benign:>10,}  ({100 - attack_pct:.1f}%)")
    print(f"  ATTACK                 : {attacks:>10,}  ({attack_pct:.1f}%)")
    print("─" * 50)

    if attacks == 0:
        print("  ✓  No attacks detected in this traffic sample.")
    elif attack_pct > 50:
        print("  ⚠  WARNING: Majority of traffic classified as ATTACK.")
    else:
        print(f"  ⚠  {attacks:,} flows flagged as potential attacks.")
    print()


def save_results(df, valid_index, preds, labels, output_path):
    """Save a CSV with predictions appended."""
    result_df = df.loc[valid_index].copy()
    result_df['prediction'] = preds
    result_df['label'] = labels
    result_df.to_csv(output_path, index=False)
    print(f"[INFO]  Results saved to: {output_path}")


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="Classify network traffic flows as BENIGN or ATTACK.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python predict.py --csv traffic.csv --model rf
  python predict.py --csv traffic.csv --model svm --output results.csv
  python predict.py --csv traffic.csv --model rf --model-dir ./my_models/
        """
    )
    parser.add_argument(
        '--csv', required=True,
        help='Path to input CSV file with network flow data'
    )
    parser.add_argument(
        '--model', required=True, choices=['rf', 'svm'],
        help='Model to use: rf (Random Forest) or svm (Support Vector Machine)'
    )
    parser.add_argument(
        '--output', default=None,
        help='(Optional) Path to save results CSV. Default: <input>_predictions.csv'
    )
    parser.add_argument(
        '--model-dir', default='./models',
        help='(Optional) Directory containing .pkl model files. Default: ./models'
    )

    args = parser.parse_args()

    # Set default output path if not provided
    if args.output is None:
        base = os.path.splitext(args.csv)[0]
        args.output = f"{base}_predictions.csv"

    # ── Pipeline ────────────────────────────────────────────────────────────
    model, scaler = load_model(args.model, args.model_dir)
    df = load_csv(args.csv)
    validate_features(df)
    X_scaled, valid_index = preprocess(df, scaler)
    preds, labels = run_predictions(model, X_scaled)
    print_summary(labels)
    save_results(df, valid_index, preds, labels, args.output)
    print("[DONE]  Prediction complete.\n")


if __name__ == '__main__':
    main()
