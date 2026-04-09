#!/usr/bin/env python
"""Test prediction pipeline to find the hang."""

import sys
import time
sys.path.insert(0, '.')

print('[1] Loading model...')
start = time.time()
from ml.model_manager import load_model
classifier, preprocessor, meta = load_model()
print(f'[1] Done in {time.time()-start:.2f}s')

print('[2] Creating dummy features...')
start = time.time()
import pandas as pd
features = {
    'flow_duration': 0.5,
    'iat_mean': 0.1,
    'iat_std': 0.05,
    'total_fwd_packets': 5,
    'total_bwd_packets': 3,
    'total_fwd_bytes': 1000,
    'total_bwd_bytes': 500,
}
for i in range(78):
    if f'feature_{i}' not in features:
        features[f'feature_{i}'] = 0.0
df = pd.DataFrame([features])
print(f'[2] Done in {time.time()-start:.2f}s')

print('[3] Transforming features...')
start = time.time()
X = preprocessor.transform(df)
print(f'[3] Done in {time.time()-start:.2f}s - Shape: {X.shape}')

print('[4] Running predictions...')
start = time.time()
results = classifier.predict_with_details(X)
print(f'[4] Done in {time.time()-start:.2f}s - Results: {len(results)}')

print('[5] Generating explanations...')
start = time.time()
from xai.explainer import explain_batch
explanations = explain_batch(classifier, X)
print(f'[5] Done in {time.time()-start:.2f}s - Explanations: {len(explanations)}')

print('[SUCCESS] All steps completed!')
