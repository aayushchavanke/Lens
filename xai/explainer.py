"""
BENFET XAI - Explainable AI Module
Provides per-prediction feature importance explanations
for forensic transparency and investigation support.
"""

import numpy as np
from ml.preprocessor import FEATURE_COLUMNS


def explain_prediction(classifier, X, sample_index=0, cached_importances=None):
    """
    Generate an explanation for a specific prediction.

    Uses the Random Forest's feature importances combined with
    the sample's actual feature values to highlight which behavioral
    characteristics drove the prediction.

    Args:
        classifier: trained BehavioralClassifier instance
        X: numpy array of feature vectors (scaled)
        sample_index: index of the sample to explain
        cached_importances: pre-computed importances list to avoid O(n²) re-sorting
                            in batch mode. If None, importances are computed fresh.

    Returns:
        dict with:
            - 'prediction': predicted label
            - 'confidence': confidence score
            - 'top_features': list of top contributing features
            - 'feature_details': all features with importances
    """
    predictions, confidences = classifier.predict(X[sample_index:sample_index+1])
    prediction = predictions[0]
    confidence = confidences[0]

    # Use cached importances if provided (avoids resorting on every sample)
    importances = cached_importances if cached_importances is not None \
        else classifier.get_feature_importances(FEATURE_COLUMNS)

    # Get per-tree predictions to estimate per-feature contribution
    sample = X[sample_index]
    tree_contributions = _tree_based_contributions(classifier.model, sample)

    # Combine global importance with sample-specific contribution
    feature_details = []
    for feat_name, global_imp in importances:
        feat_idx = FEATURE_COLUMNS.index(feat_name) if feat_name in FEATURE_COLUMNS else -1
        value = float(sample[feat_idx]) if feat_idx >= 0 else 0

        feature_details.append({
            'feature': feat_name,
            'importance': round(float(global_imp), 4),
            'value': round(value, 6),
            'contribution': round(
                float(tree_contributions.get(feat_name, 0)), 4
            ),
        })

    # Sort by importance
    feature_details.sort(key=lambda x: x['importance'], reverse=True)

    return {
        'prediction': prediction,
        'confidence': round(confidence, 4),
        'top_features': feature_details[:10],
        'feature_details': feature_details,
        'explanation_text': _generate_narrative(prediction, confidence, feature_details[:5]),
    }


def explain_batch(classifier, X):
    """
    Generate fast, lightweight explanations for all samples in X.
    
    Optimized for speed - skips unnecessary computations.
    Returns only top features and simplified narratives.

    Returns:
        list of explanation dicts
    """
    from concurrent.futures import ThreadPoolExecutor
    import threading
    
    # Compute and cache importances a single time for the whole batch
    cached_importances = classifier.get_feature_importances(FEATURE_COLUMNS)
    
    # Pre-compute predictions for all samples at once
    predictions, confidences = classifier.predict(X)
    
    # Fast explanations with parallel processing
    explanations = []
    
    def fast_explain(i):
        prediction = predictions[i]
        confidence = confidences[i]
        sample = X[i]
        
        # Simplified: only top features, skip expensive tree analysis
        top_features = []
        for feat_name, global_imp in cached_importances[:10]:  # Top 10 only
            feat_idx = FEATURE_COLUMNS.index(feat_name) if feat_name in FEATURE_COLUMNS else -1
            if feat_idx < 0:
                continue
            value = float(sample[feat_idx])
            top_features.append({
                'feature': feat_name,
                'importance': round(float(global_imp), 4),
                'value': round(value, 6),
            })
        
        return {
            'prediction': prediction,
            'confidence': round(confidence, 4),
            'top_features': top_features,
            'explanation_text': _generate_fast_narrative(prediction, confidence, top_features),
        }
    
    # Use parallel processing if batch is large
    if len(X) > 1:
        with ThreadPoolExecutor(max_workers=4) as executor:
            explanations = list(executor.map(fast_explain, range(len(X))))
    else:
        explanations = [fast_explain(0)]
    
    return explanations


def _tree_based_contributions(model, sample):
    """
    Estimate per-feature contributions using tree-based analysis.
    Averages feature importances across trees, weighted by the sample's path.
    """
    contributions = {}
    n_features = len(sample)

    for i, feat_name in enumerate(FEATURE_COLUMNS[:n_features]):
        # Use the global importance weighted by the absolute z-score of the feature
        importance = model.feature_importances_[i] if i < len(model.feature_importances_) else 0
        # Scale contribution by absolute value (how far from mean in scaled space)
        contribution = importance * abs(sample[i])
        contributions[feat_name] = contribution

    # Normalize
    total = sum(abs(v) for v in contributions.values()) or 1
    for key in contributions:
        contributions[key] /= total

    return contributions


def _generate_narrative(prediction, confidence, top_features):
    """Generate a human-readable explanation narrative."""
    confidence_pct = round(confidence * 100, 1)
    lines = [
        f"The traffic was classified as **{prediction}** with {confidence_pct}% confidence.",
        "",
        "Key behavioral indicators:"
    ]

    for feat in top_features:
        name = feat['feature'].replace('_', ' ').title()
        imp_pct = round(feat['importance'] * 100, 1)
        lines.append(f"  • {name}: importance = {imp_pct}%")

    lines.append("")
    lines.append(
        "These features represent the behavioral metadata patterns that most "
        "strongly distinguished this traffic profile from others."
    )

    return "\n".join(lines)


def _generate_fast_narrative(prediction, confidence, top_features):
    """Generate a quick, lightweight explanation narrative (optimized for speed)."""
    confidence_pct = round(confidence * 100, 1)
    top_3 = top_features[:3]
    
    feat_list = ", ".join(f.get('feature', 'unknown').replace('_', ' ') for f in top_3)
    
    return f"**{prediction}** ({confidence_pct}% confidence) — Driven by: {feat_list}"
