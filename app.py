"""
The Obsidian Lens — Flask Backend (v4 Rebuild)
Minimalistic professional network forensic tool.
Two ingestion modes (Live Capture / PCAP Upload) → 78-parameter analysis →
White/Black identity categorization → SQLite fingerprint DB → Block/Unblock.
"""

import os
import sys
import json
import uuid
import traceback
from datetime import datetime
from flask import Flask, request, jsonify, send_file

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config
from config import (UPLOAD_FOLDER, MODELS_FOLDER, REPORTS_FOLDER,
                     ANALYSIS_FOLDER, ALLOWED_EXTENSIONS)

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = config.MAX_CONTENT_LENGTH


# ─── CORS ────────────────────────────────────────────────────────────────

@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    return response


# ─── Analysis Cache ──────────────────────────────────────────────────────

analysis_cache = {}


def _load_cache_from_disk():
    if not os.path.exists(ANALYSIS_FOLDER):
        return
    for fname in os.listdir(ANALYSIS_FOLDER):
        if fname.endswith('.json'):
            aid = fname[:-5]
            fpath = os.path.join(ANALYSIS_FOLDER, fname)
            try:
                with open(fpath, 'r') as f:
                    analysis_cache[aid] = json.load(f)
            except (json.JSONDecodeError, OSError):
                pass


_load_cache_from_disk()


# ─── Helpers ─────────────────────────────────────────────────────────────

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def get_analysis(analysis_id):
    if analysis_id in analysis_cache:
        return analysis_cache[analysis_id]
    cache_path = os.path.join(ANALYSIS_FOLDER, f"{analysis_id}.json")
    if os.path.exists(cache_path):
        with open(cache_path, 'r') as f:
            data = json.load(f)
        analysis_cache[analysis_id] = data
        return data
    return None


def save_analysis(analysis_id, data):
    analysis_cache[analysis_id] = data
    cache_path = os.path.join(ANALYSIS_FOLDER, f"{analysis_id}.json")
    with open(cache_path, 'w') as f:
        json.dump(data, f, default=str)


def _valid_analysis_id(analysis_id):
    import re
    return bool(re.match(r'^[a-f0-9]{6,16}$', analysis_id))


# ═════════════════════════════════════════════════════════════════════════
#  API: PCAP UPLOAD
# ═════════════════════════════════════════════════════════════════════════

@app.route('/api/upload', methods=['POST'])
def upload_pcap():
    """Upload a PCAP file for analysis."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file part in the request'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': f'Invalid file type. Allowed: {", ".join(ALLOWED_EXTENSIONS)}'}), 400

    analysis_id = str(uuid.uuid4())[:8]
    filename = f"{analysis_id}_{file.filename}"
    filepath = os.path.join(UPLOAD_FOLDER, filename)

    try:
        file.save(filepath)
        file_size = os.path.getsize(filepath)
        print(f"[UPLOAD] Saved: {filename} ({file_size} bytes)")

        save_analysis(analysis_id, {
            'id': analysis_id,
            'filename': file.filename,
            'filepath': filepath,
            'status': 'uploaded',
            'source': 'upload',
            'uploaded_at': datetime.now().isoformat(),
        })

        return jsonify({
            'analysis_id': analysis_id,
            'filename': file.filename,
            'status': 'uploaded',
        })
    except Exception as e:
        return jsonify({'error': f'Upload failed: {str(e)}'}), 500


# ═════════════════════════════════════════════════════════════════════════
#  API: LIVE CAPTURE
# ═════════════════════════════════════════════════════════════════════════

@app.route('/api/capture/interfaces', methods=['GET'])
def list_interfaces():
    from core.live_capture import get_interfaces
    return jsonify({'interfaces': get_interfaces()})


@app.route('/api/capture/start', methods=['POST'])
def start_capture():
    from core.live_capture import start_capture as _start
    data = request.get_json(silent=True) or {}
    result = _start(
        interface=data.get('interface'),
        duration=data.get('duration', 60),
        packet_count=data.get('packet_count', 10000),
    )
    return jsonify(result)


@app.route('/api/capture/stop', methods=['POST'])
def stop_capture():
    from core.live_capture import stop_capture as _stop
    result = _stop()

    if result.get('output_file') and os.path.exists(result.get('output_file', '')):
        analysis_id = str(uuid.uuid4())[:8]
        filename = os.path.basename(result['output_file'])

        save_analysis(analysis_id, {
            'id': analysis_id,
            'filename': filename,
            'filepath': result['output_file'],
            'status': 'uploaded',
            'source': 'live_capture',
            'packets_captured': result['packets_captured'],
            'capture_duration': result['duration'],
            'uploaded_at': datetime.now().isoformat(),
        })

        result['analysis_id'] = analysis_id

    return jsonify(result)

@app.route('/api/capture/status', methods=['GET'])
def capture_status():
    from core.live_capture import get_capture_status
    return jsonify(get_capture_status())

@app.route('/api/analysis/<analysis_id>', methods=['DELETE'])
def delete_analysis_record(analysis_id):
    if not _valid_analysis_id(analysis_id):
        return jsonify({'error': 'Invalid analysis ID'}), 400
    cache_path = os.path.join(ANALYSIS_FOLDER, f"{analysis_id}.json")
    if os.path.exists(cache_path):
        os.remove(cache_path)
    if analysis_id in analysis_cache:
        del analysis_cache[analysis_id]
        
    return jsonify({'success': True}), 200

# ═════════════════════════════════════════════════════════════════════════
#  XAI HEURISTIC MAPPINGS
# ═════════════════════════════════════════════════════════════════════════

XAI_INSIGHTS_DICT = {
    'flow_duration': 'Abnormally long flow duration implies a persistent connection, typical of Remote Access Trojans (RATs) or Command & Control beacons.',
    'fwd_packet': 'High volume or erratic forward packet variance indicates an outbound data exfiltration attempt or aggressive request flooding.',
    'bwd_packet': 'Large backward packet anomalies suggest the system is actively fetching heavy secondary payloads from an external staging server.',
    'flow_bytes': 'A spike in network throughput matches expected bandwidth saturation techniques used in volumetric DDoS attacks.',
    'fin_flag': 'Rapid accumulation of FIN flags signifies constant tearing down of connections, typical in exhaustive port scanning or stealth network mapping.',
    'down/up': 'An imbalanced connection ratio strongly suggests an automated botnet script rigidly fetching commands without standard human interaction delays.',
    'init_win': 'Anomalous initial window bytes are common in forged TCP handshakes used to bypass standard firewall state tracking.',
    'iat': 'Irregular inter-arrival timing (IAT) signatures reveal algorithmic heartbeats attempting to mimic human browsing behavior to evade detection.',
}

def generate_insights(top_features, is_malicious, threat_type):
    insights = []
    base_verdict = f'a confirmed {threat_type}' if is_malicious else 'Safe Network Noise'
    
    for f_name, weight in top_features:
        insight_found = False
        f_lower = f_name.lower().replace(' ', '_')
        for key, text in XAI_INSIGHTS_DICT.items():
            if key in f_lower:
                insights.append(f"[{f_name}] ({weight*100:.1f}% Weight): {text} This mathematical anomaly heavily forced the AI to classify this as {base_verdict}.")
                insight_found = True
                break
        if not insight_found:
             insights.append(f"[{f_name}] ({weight*100:.1f}% Weight): The neural network identified extreme structural variance in this parameter while forming the {base_verdict} profile.")
    return insights

# ═════════════════════════════════════════════════════════════════════════

@app.route('/api/analyze/<analysis_id>', methods=['GET'])
def run_analysis(analysis_id):
    """
    Full pipeline: Parse PCAP → Extract 78 features → Classify →
    Categorize White/Black → Store identities in SQLite DB.
    """
    if not _valid_analysis_id(analysis_id):
        return jsonify({'error': 'Invalid analysis ID'}), 400
    record = get_analysis(analysis_id)
    if not record:
        return jsonify({'error': 'Analysis not found'}), 404

    try:
        from core.pcap_parser import parse_pcap
        from core.feature_extractor import extract_features
        from core.flow_analyzer import analyze_flows
        from core.identity_db import upsert_identity
        import pandas as pd

        filepath = record['filepath']
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"PCAP file not found: {filepath}")

        # Step 1: Parse PCAP
        print(f"[ANALYZE] Parsing {analysis_id}...")
        parsed = parse_pcap(filepath)

        if parsed['metadata']['total_packets'] == 0:
            raise ValueError('No packets found in PCAP file.')

        # Step 2: Extract 78 features
        print(f"[ANALYZE] Extracting 78-parameter features...")
        features_df = extract_features(parsed)

        if features_df.empty:
            raise ValueError('No flows could be extracted.')

        # Step 3: Flow analysis
        flow_analysis = analyze_flows(parsed)

        # Step 4: Classify (if model exists)
        predictions = []
        explanations = []
        identities_created = []

        try:
            from ml.model_manager import load_model
            classifier, preprocessor, model_meta = load_model()

            X = preprocessor.transform(features_df)
            results = classifier.predict_with_details(X)

            # Step 5: Store each classified flow as an identity in DB
            for i, pred in enumerate(results):
                row = features_df.iloc[i]
                src_ip = row.get('src_ip', '')
                dst_ip = row.get('dst_ip', '')
                ja3_hash = ''

                # Determine category
                if pred['is_malicious']:
                    category = 'black'
                    threat_type = pred['threat_type']
                else:
                    category = 'white'
                    threat_type = 'Safe Traffic'

                identity_id = upsert_identity(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    category=category,
                    threat_type=threat_type,
                    confidence=pred['confidence'],
                    ja3_hash=ja3_hash,
                    analysis_id=analysis_id,
                )

                pred['identity_id'] = identity_id
                pred['dst_ip'] = dst_ip
                identities_created.append(identity_id)

            predictions = results
            from ml.preprocessor import FEATURE_COLUMNS
            feature_imp = classifier.get_feature_importances(FEATURE_COLUMNS)
            
            # Generate actionable text insights using top 3 features
            top_3 = feature_imp[:3]
            sample_threat_type = results[0]['threat_type'] if results else 'Unknown'
            sample_is_malicious = results[0]['is_malicious'] if results else False
            generated_insights = generate_insights(top_3, sample_is_malicious, sample_threat_type)
            
            explanations = [{
                'top_features': feature_imp[:10],
                'insights': generated_insights
            }]

        except FileNotFoundError:
            for i in range(len(features_df)):
                row = features_df.iloc[i]
                src_ip = row.get('src_ip', '')
                dst_ip = row.get('dst_ip', '')

                identity_id = upsert_identity(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    category='white',
                    threat_type='Unclassified (No Model)',
                    confidence=0.0,
                    analysis_id=analysis_id,
                )
                identities_created.append(identity_id)

        # Save results
        record.update({
            'status': 'analyzed',
            'metadata': parsed['metadata'],
            'flow_analysis': flow_analysis,
            'features': features_df.to_dict(orient='records'),
            'predictions': predictions,
            'explanations': explanations,
            'identities_created': identities_created,
            'analyzed_at': datetime.now().isoformat(),
        })

        save_analysis(analysis_id, record)
        print(f"[ANALYZE] Complete: {len(features_df)} flows, {len(identities_created)} identities")

        return jsonify({
            'analysis_id': analysis_id,
            'status': 'analyzed',
            'metadata': parsed['metadata'],
            'total_flows': len(features_df),
            'predictions': predictions,
            'identities_created': len(set(identities_created)),
        })

    except Exception as e:
        print(f"[ERROR] Analysis failed: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 500


# ═════════════════════════════════════════════════════════════════════════
#  API: IDENTITY DATABASE
# ═════════════════════════════════════════════════════════════════════════

@app.route('/api/identities', methods=['GET'])
def list_identities():
    """Get all tracked identities (White and Black users)."""
    from core.identity_db import get_all_identities
    identities = get_all_identities()

    white = [i for i in identities if i['category'] == 'white']
    black = [i for i in identities if i['category'] == 'black']

    return jsonify({
        'total': len(identities),
        'white_users': white,
        'black_users': black,
    })


@app.route('/api/identities/<int:identity_id>', methods=['GET'])
def get_identity_detail(identity_id):
    """Get full details for a specific identity."""
    from core.identity_db import get_identity
    identity = get_identity(identity_id)
    if not identity:
        return jsonify({'error': 'Identity not found'}), 404
    return jsonify(identity)


@app.route('/api/identities/<int:identity_id>/block', methods=['POST'])
def block_identity_endpoint(identity_id):
    """Block a malicious identity from the network by deploying real Windows Firewall rules."""
    from core.identity_db import block_identity, get_identity
    identity = get_identity(identity_id)
    if not identity:
        return jsonify({'error': 'Identity not found'}), 404
    
    # Actually block through Windows Firewall! (Elevated)
    import subprocess
    block_success = []
    for ip in identity.get('associated_ips', []):
        try:
            rule_name = f"OBSIDIAN_BLOCK_{ip}"
            ps_command = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip}; netsh advfirewall firewall add rule name="{rule_name}_OUT" dir=out action=block remoteip={ip}'
            cmd = f'powershell -Command "Start-Process powershell -ArgumentList \'-Command {ps_command}\' -Verb RunAs -WindowStyle Hidden"'
            subprocess.run(cmd, shell=True, check=False)
            block_success.append(ip)
        except Exception as e:
            print(f"Failed to elevate firewall block for {ip}: {e}")

    block_identity(identity_id)
    return jsonify({'status': 'blocked', 'identity_id': identity_id, 'firewall_blocked_ips': block_success})


@app.route('/api/identities/<int:identity_id>/unblock', methods=['POST'])
def unblock_identity_endpoint(identity_id):
    """Unblock an identity."""
    from core.identity_db import unblock_identity, get_identity
    identity = get_identity(identity_id)
    if not identity:
        return jsonify({'error': 'Identity not found'}), 404
        
    import subprocess
    unblock_success = []
    for ip in identity.get('associated_ips', []):
        try:
            rule_name = f"OBSIDIAN_BLOCK_{ip}"
            ps_command = f'netsh advfirewall firewall delete rule name="{rule_name}"; netsh advfirewall firewall delete rule name="{rule_name}_OUT"'
            cmd = f'powershell -Command "Start-Process powershell -ArgumentList \'-Command {ps_command}\' -Verb RunAs -WindowStyle Hidden"'
            subprocess.run(cmd, shell=True, check=False)
            unblock_success.append(ip)
        except Exception as e:
            print(f"Failed to elevate firewall unblock for {ip}: {e}")
            
    unblock_identity(identity_id)
    return jsonify({'status': 'unblocked', 'identity_id': identity_id, 'firewall_unblocked_ips': unblock_success})


# ═════════════════════════════════════════════════════════════════════════
#  API: NETWORK HEALTH
# ═════════════════════════════════════════════════════════════════════════

@app.route('/api/network-health', methods=['GET'])
def network_health():
    """Get network health score and summary stats."""
    from core.identity_db import get_network_health
    return jsonify(get_network_health())


# ═════════════════════════════════════════════════════════════════════════
#  API: TRAIN MODEL
# ═════════════════════════════════════════════════════════════════════════

@app.route('/api/train', methods=['POST'])
def train_model():
    """Train the weighted behavioral fingerprinting model from the persistent dataset."""
    try:
        import pandas as pd
        from ml.dataset_generator import generate_dataset
        from ml.preprocessor import Preprocessor
        from ml.classifier import BehavioralClassifier
        from ml.model_manager import save_model

        dataset_path = os.path.join(BASE_DIR, 'data', 'training_data.csv')
        os.makedirs(os.path.dirname(dataset_path), exist_ok=True)

        if os.path.exists(dataset_path):
            print("[TRAIN] Loading dataset from persistent CSV...")
            df = pd.read_csv(dataset_path)
        else:
            print("[TRAIN] Generating initial dataset...")
            data = request.get_json(silent=True) or {}
            n_samples = data.get('n_samples_per_profile', 200)
            df = generate_dataset(n_samples_per_profile=n_samples)
            df.to_csv(dataset_path, index=False)

        preprocessor = Preprocessor()
        X, y = preprocessor.fit_transform(df)

        classifier = BehavioralClassifier()
        metrics = classifier.train(X, y)

        save_model(classifier, preprocessor, metadata=metrics)

        return jsonify({
            'status': 'trained',
            'metrics': metrics,
            'dataset_size': len(df),
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/feedback/<analysis_id>', methods=['POST'])
def apply_feedback(analysis_id):
    """
    Continuous Learning: 
    Take user feedback (a new label) for an analysis, append its features 
    to the persistent dataset, and instantly retrain the model.
    """
    if not _valid_analysis_id(analysis_id):
        return jsonify({'error': 'Invalid analysis ID'}), 400
    record = get_analysis(analysis_id)
    if not record:
        return jsonify({'error': 'Analysis not found'}), 404

    data = request.get_json(silent=True) or {}
    new_label = data.get('label')
    if not new_label:
        return jsonify({'error': 'Missing label'}), 400

    try:
        import pandas as pd
        
        # 1. Get the extracted features from this analysis
        # We need to re-extract or load from saved analysis
        # Luckily, get_analysis(analysis_id) should have the raw flow_analysis. 
        # But we need the 78 strict features. We'll extract them again from PCAP.
        from core.pcap_parser import parse_pcap
        from core.feature_extractor import extract_features
        
        parsed = parse_pcap(record['filepath'])
        features_df = extract_features(parsed)
        
        if features_df.empty:
            return jsonify({'error': 'No flows to learn from in this PCAP'}), 400
            
        # 2. Assign the new label to all flows in this PCAP
        features_df['label'] = new_label
        
        # We don't save IP/Mac strings to the ML dataset
        if 'src_ip' in features_df.columns:
            features_df = features_df.drop(columns=['src_ip', 'dst_ip', 'src_port', 'dst_port', 'mac_address', 'ja3_hash'], errors='ignore')

        # 3. Append to dataset CSV
        dataset_path = os.path.join(BASE_DIR, 'data', 'training_data.csv')
        
        # If it doesn't exist, we must train the base model first
        if not os.path.exists(dataset_path):
            from ml.dataset_generator import generate_dataset
            base_df = generate_dataset(n_samples_per_profile=100)
            base_df.to_csv(dataset_path, index=False)
            
        # Append without writing header if it already exists
        features_df.to_csv(dataset_path, mode='a', header=not os.path.exists(dataset_path), index=False)

        # 4. Trigger Retraining
        from ml.preprocessor import Preprocessor
        from ml.classifier import BehavioralClassifier
        from ml.model_manager import save_model

        full_df = pd.read_csv(dataset_path)
        preprocessor = Preprocessor()
        X, y = preprocessor.fit_transform(full_df)

        classifier = BehavioralClassifier()
        metrics = classifier.train(X, y)
        save_model(classifier, preprocessor, metadata=metrics)
        
        return jsonify({
            'status': 'success',
            'message': f'Model retrained with {len(features_df)} new flows as {new_label}',
            'dataset_size': len(full_df),
            'metrics': metrics
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/feedback/bulk', methods=['POST'])
def apply_bulk_feedback():
    """
    Continuous Learning (Batch Engine):
    Process multiple analyses safely in a single thread to avoid CSV/PKL race conditions.
    """
    data = request.get_json(silent=True) or {}
    new_label = data.get('label')
    analysis_ids = data.get('analysis_ids', [])
    
    if not new_label or not analysis_ids:
        return jsonify({'error': 'Missing label or analysis IDs'}), 400
        
    try:
        import pandas as pd
        from core.pcap_parser import parse_pcap
        from core.feature_extractor import extract_features
        
        all_features = []
        
        for ans_id in analysis_ids:
            record = get_analysis(ans_id)
            if not record: continue
            
            parsed = parse_pcap(record['filepath'])
            f_df = extract_features(parsed)
            if not f_df.empty:
                all_features.append(f_df)
                
        if not all_features:
            return jsonify({'error': 'No valid flows extracted from selected captures.'}), 400
            
        # Combine all features
        features_df = pd.concat(all_features, ignore_index=True)
        features_df['label'] = new_label
        
        # Clean addresses
        if 'src_ip' in features_df.columns:
            features_df = features_df.drop(columns=['src_ip', 'dst_ip', 'src_port', 'dst_port', 'mac_address', 'ja3_hash'], errors='ignore')

        # Append to CSV precisely once
        dataset_path = os.path.join(BASE_DIR, 'data', 'training_data.csv')
        
        if not os.path.exists(dataset_path):
            from ml.dataset_generator import generate_dataset
            base_df = generate_dataset(n_samples_per_profile=100)
            base_df.to_csv(dataset_path, index=False)
            
        features_df.to_csv(dataset_path, mode='a', header=not os.path.exists(dataset_path), index=False)

        # Trigger Single Retrain
        from ml.preprocessor import Preprocessor
        from ml.classifier import BehavioralClassifier
        from ml.model_manager import save_model

        full_df = pd.read_csv(dataset_path)
        preprocessor = Preprocessor()
        X, y = preprocessor.fit_transform(full_df)

        classifier = BehavioralClassifier()
        metrics = classifier.train(X, y)
        save_model(classifier, preprocessor, metadata=metrics)
        
        return jsonify({
            'status': 'success',
            'message': f'Model batch-retrained with {len(features_df)} combined flows.',
            'dataset_size': len(full_df),
            'metrics': metrics
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/api/models', methods=['GET'])
def list_models():
    """Get info about the current trained model."""
    from ml.model_manager import model_exists, get_model_info
    return jsonify({
        'model_exists': model_exists(),
        'model': get_model_info(),
    })


# ═════════════════════════════════════════════════════════════════════════
#  API: DASHBOARD SUMMARY
# ═════════════════════════════════════════════════════════════════════════

@app.route('/api/summary', methods=['GET'])
def dashboard_summary():
    """Combined summary for the professional dashboard."""
    from ml.model_manager import model_exists, get_model_info
    from core.identity_db import get_network_health, get_all_identities

    health = get_network_health()
    identities = get_all_identities()

    # Gather recent analyses
    analyses = []
    if os.path.exists(ANALYSIS_FOLDER):
        # Sort files by modification time (newest first)
        files = [f for f in os.listdir(ANALYSIS_FOLDER) if f.endswith('.json')]
        files.sort(key=lambda x: os.path.getmtime(os.path.join(ANALYSIS_FOLDER, x)), reverse=True)
        
        for f in files[:10]:
            try:
                with open(os.path.join(ANALYSIS_FOLDER, f), 'r') as fh:
                    data = json.load(fh)
                analyses.append({
                    'id': data.get('id', f.replace('.json', '')),
                    'filename': data.get('filename', 'unknown'),
                    'status': data.get('status', 'unknown'),
                    'source': data.get('source', 'upload'),
                    'uploaded_at': data.get('uploaded_at', ''),
                })
            except Exception:
                pass

    return jsonify({
        'health': health,
        'total_identities': len(identities),
        'white_count': health['white_count'],
        'black_count': health['black_count'],
        'blocked_count': health['blocked_count'],
        'model_exists': model_exists(),
        'model': get_model_info(),
        'recent_analyses': analyses,
    })


# ═════════════════════════════════════════════════════════════════════════
#  API: DEEP FORENSIC ANALYSIS
# ═════════════════════════════════════════════════════════════════════════

@app.route('/api/analysis/<analysis_id>', methods=['GET'])
def get_analysis_details(analysis_id):
    """Return the detailed JSON report for Deep Forensic Analysis."""
    if not _valid_analysis_id(analysis_id):
        return jsonify({'error': 'Invalid analysis ID'}), 400
        
    analysis_file = os.path.join(ANALYSIS_FOLDER, f"{analysis_id}.json")
    if not os.path.exists(analysis_file):
        return jsonify({'error': 'Analysis not found'}), 404
        
    with open(analysis_file, 'r') as fh:
        data = json.load(fh)
        
    return jsonify(data)


# ═════════════════════════════════════════════════════════════════════════
#  API: PDF REPORT
# ═════════════════════════════════════════════════════════════════════════

@app.route('/api/report/<analysis_id>', methods=['GET'])
def generate_report(analysis_id):
    """Generate and download a PDF forensic report."""
    if not _valid_analysis_id(analysis_id):
        return jsonify({'error': 'Invalid analysis ID'}), 400
    record = get_analysis(analysis_id)
    if not record:
        return jsonify({'error': 'Analysis not found'}), 404

    try:
        from reports.pdf_report import generate_pdf_report

        report_path = generate_pdf_report(
            analysis_id=analysis_id,
            analysis_data=record.get('flow_analysis', {}),
            predictions=record.get('predictions', []),
            explanations=record.get('explanations', []),
            topology={},
            metadata=record.get('metadata', {}),
        )

        return send_file(
            report_path,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f'ObsidianLens_Report_{analysis_id}.pdf',
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ═════════════════════════════════════════════════════════════════════════
#  APP STARTUP & MLOps AUTO-INITIALIZATION
# ═════════════════════════════════════════════════════════════════════════

def auto_initialize_system():
    """Silently ensure the model and dataset exist on startup."""
    from ml.model_manager import model_exists
    
    if not model_exists():
        print("[*] No model detected. Initiating automated MLOps startup...")
        try:
            import pandas as pd
            from ml.dataset_generator import generate_dataset
            from ml.preprocessor import Preprocessor
            from ml.classifier import BehavioralClassifier
            from ml.model_manager import save_model

            dataset_path = os.path.join(BASE_DIR, 'data', 'training_data.csv')
            os.makedirs(os.path.dirname(dataset_path), exist_ok=True)

            if not os.path.exists(dataset_path):
                print("  [->] Generating base pre-trained dataset...")
                df = generate_dataset(n_samples_per_profile=150)
                df.to_csv(dataset_path, index=False)
            else:
                print("  [->] Base dataset found. Loading...")
                df = pd.read_csv(dataset_path)

            print("  [->] Training Weighted Random Forest...")
            preprocessor = Preprocessor()
            X, y = preprocessor.fit_transform(df)

            classifier = BehavioralClassifier()
            metrics = classifier.train(X, y)
            save_model(classifier, preprocessor, metadata=metrics)
            print("[✓] MLOps startup complete. System ready to detect threats.")
        except Exception as e:
            print(f"[!] Error during automated MLOps startup: {e}")

# ═════════════════════════════════════════════════════════════════════════
#  RUN
# ═════════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    print("\n" + "=" * 60)
    print("   THE OBSIDIAN LENS — Network Forensic Tool")
    print("   78-Parameter Behavioral Analysis | Identity Tracking")
    print("   Server running at http://localhost:5000")
    print("=" * 60 + "\n")
    auto_initialize_system()
    app.run(debug=False, host='0.0.0.0', port=5000)
