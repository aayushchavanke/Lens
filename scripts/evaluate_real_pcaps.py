"""
BENFET - Real-World Dataset Evaluation
Downloads public, real-world PCAP files and evaluates BENFET's behavioral fingerprinting
engine against them. Demonstrates how well synthetic-trained models perform on real data.
"""
import os
import sys
import urllib.request
import pandas as pd
import json
import traceback

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.pcap_parser import parse_pcap
from core.feature_extractor import extract_features
from ml.model_manager import load_model

PCAP_SOURCES = {
    'http_browsing': 'https://raw.githubusercontent.com/chrissanders/packets/master/http.pcap',
    'dns_traffic': 'https://raw.githubusercontent.com/chrissanders/packets/master/dns.pcap',
    'smb_transfer': 'https://raw.githubusercontent.com/chrissanders/packets/master/smb.pcap',
    'dhcp_traffic': 'https://raw.githubusercontent.com/chrissanders/packets/master/dhcp.pcap',
    'ipv6_traffic': 'https://raw.githubusercontent.com/chrissanders/packets/master/ipv6.pcap'
}

DATASETS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'datasets', 'real_world'))

def download_pcaps():
    print("="*60)
    print("[Downloading] Real-World PCAP Datasets...")
    os.makedirs(DATASETS_DIR, exist_ok=True)
    
    downloaded_files = {}
    for name, url in PCAP_SOURCES.items():
        filepath = os.path.join(DATASETS_DIR, f"{name}.pcap")
        if not os.path.exists(filepath):
            print(f"  Fetching {name}...")
            try:
                urllib.request.urlretrieve(url, filepath)
                print(f"    ✓ Saved to {filepath}")
            except Exception as e:
                print(f"    ✗ Failed to download {name}: {e}")
        else:
            print(f"  ✓ {name} already exists.")
        
        if os.path.exists(filepath):
            downloaded_files[name] = filepath
            
    return downloaded_files

def evaluate_real_data(downloaded_files):
    print("\n" + "="*60)
    print("[Evaluating] BENFET on Real-World Traffic Data")
    
    try:
        model, preprocessor, meta = load_model()
        print(f"  ✓ Loaded BENFET Classifier (Trained on {meta.get('date', 'Unknown')})")
    except Exception as e:
        print(f"  ✗ Failed to load model. Has it been trained? Error: {e}")
        return

    results = []

    for name, filepath in downloaded_files.items():
        print(f"\n[Analyzing] {name} ({os.path.basename(filepath)})")
        try:
            # 1. Parse PCAP
            print("  - Parsing PCAP...")
            parsed_data = parse_pcap(filepath)
            total_flows = parsed_data['metadata']['total_flows']
            print(f"    ✓ Found {total_flows} directional flows.")
            
            if total_flows == 0:
                print("    ! No flows extracted.")
                continue

            # 2. Extract 77 Behavioral Features
            print("  - Extracting 77-dimensional behavioral features...")
            features = extract_features(parsed_data)
            print(f"    ✓ Extracted features for {len(features)} flows.")
            
            if len(features) == 0:
                print("    ! No features extracted.")
                continue

            # 3. Preprocess & Predict
            print("  - Running behavioral classifier...")
            df = pd.DataFrame(features)
            X = preprocessor.transform(df)
            
            predictions, confidences = model.predict(X)
            
            # Aggregate predictions for this PCAP
            pred_counts = pd.Series(predictions).value_counts().to_dict()
            df['prediction'] = predictions
            df['confidence'] = confidences
            
            # Show top predictions
            print(f"    ✓ Predictions for {name}:")
            for pred, count in pred_counts.items():
                avg_conf = df[df['prediction'] == pred]['confidence'].mean()
                print(f"      - {pred}: {count} flows (Avg Confidence: {avg_conf*100:.1f}%)")
                
            results.append({
                'dataset': name,
                'total_flows': len(features),
                'primary_prediction': list(pred_counts.keys())[0],
                'primary_confidence': float(df[df['prediction'] == list(pred_counts.keys())[0]]['confidence'].mean()),
                'all_predictions': pred_counts
            })
            
        except Exception as e:
            print(f"  ✗ Error processing {name}: {e}")
            traceback.print_exc()

    # Document "The Synthetic Gap"
    print("\n" + "="*60)
    print("📊 REAL-WORLD EVALUATION SUMMARY")
    print("="*60)
    for res in results:
        print(f"Dataset: {res['dataset']:<15} | Primary Pred: {res['primary_prediction']:<15} ({res['primary_confidence']*100:.1f}%) | Flows: {res['total_flows']}")
    
    print("\n📌 Research Finding: 'The Synthetic Gap'")
    print("Notice if the model (trained on idealized synthetic profiles) accurately maps these real-world")
    print("PCAPs to sensible categories. For example, 'http_browsing' should ideally map to 'web_browser'.")
    print("If it misclassifies them (e.g., as 'malware_c2' or 'voip_user'), this experimentally proves the")
    print("limitations of training purely on synthetic data—a key academic finding that justifies the need")
    print("for fine-tuning on real-world datasets like CICIDS2017.")
    
    with open('real_world_report.json', 'w') as f:
        json.dump(results, f, indent=4)
    print("\nSaved detailed results to real_world_report.json")

if __name__ == "__main__":
    files = download_pcaps()
    evaluate_real_data(files)
