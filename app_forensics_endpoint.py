
# ═════════════════════════════════════════════════════════════════════════
#  API: FORENSIC INSIGHTS (for RecordsTable panel)
# ═════════════════════════════════════════════════════════════════════════
# ADD THIS BLOCK to app.py, right after the existing /api/analysis/<id> GET route (~line 787)

@app.route('/api/forensics/<analysis_id>', methods=['GET'])
def get_forensic_insights(analysis_id):
    """
    Return forensic insight data for the RecordsTable panel.
    Includes: top features, XAI insights, suggestions, and prediction summary.
    """
    if not _valid_analysis_id(analysis_id):
        return jsonify({'error': 'Invalid analysis ID'}), 400

    record = get_analysis(analysis_id)
    if not record:
        return jsonify({'error': 'Analysis not found'}), 404

    predictions = record.get('predictions', [])
    explanations = record.get('explanations', [])
    metadata = record.get('metadata', {})

    # Re-generate insights if explanations are missing (e.g. no model at analysis time)
    if not explanations and predictions:
        try:
            from ml.model_manager import load_model
            from ml.preprocessor import FEATURE_COLUMNS
            classifier, _, _ = load_model()
            feature_imp = classifier.get_feature_importances(FEATURE_COLUMNS)
            top_3 = feature_imp[:3]
            sample_threat = predictions[0].get('threat_type', 'Unknown') if predictions else 'Unknown'
            sample_malicious = predictions[0].get('is_malicious', False) if predictions else False
            generated_insights = generate_insights(top_3, sample_malicious, sample_threat)
            explanations = [{'top_features': feature_imp[:10], 'insights': generated_insights}]
        except Exception:
            pass

    return jsonify({
        'analysis_id': analysis_id,
        'filename': record.get('filename', 'unknown'),
        'status': record.get('status', 'unknown'),
        'source': record.get('source', 'upload'),
        'uploaded_at': record.get('uploaded_at', ''),
        'analyzed_at': record.get('analyzed_at', ''),
        'total_flows': len(predictions),
        'identities_created': len(set(record.get('identities_created', []))),
        'metadata': metadata,
        'predictions': predictions,
        'explanations': explanations,
    })
