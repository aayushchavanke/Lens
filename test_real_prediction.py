#!/usr/bin/env python
"""Test prediction with real features from analysis cache."""

import sys
import os
import json
import time
sys.path.insert(0, '.')

from config import ANALYSIS_FOLDER

# Get the latest analysis
print('[1] Finding latest analysis...')
analyses = [f[:-5] for f in os.listdir(ANALYSIS_FOLDER) if f.endswith('.json')]
if not analyses:
    print('❌ No analyses found')
    sys.exit(1)

latest_id = analyses[-1]
print(f'[1] Latest analysis: {latest_id}')

# Load analysis
print('[2] Loading analysis data...')
start = time.time()
with open(os.path.join(ANALYSIS_FOLDER, f'{latest_id}.json')) as f:
    record = json.load(f)
print(f'[2] Done in {time.time()-start:.2f}s')

if not record.get('features'):
    print('❌ No features in analysis')
    sys.exit(1)

print(f'[3] Loading model...')
start = time.time()
from ml.model_manager import load_model
from ml.preprocessor import Preprocessor
classifier, preprocessor, meta = load_model()
print(f'[3] Done in {time.time()-start:.2f}s')

print(f'[4] Creating dataframe from {len(record["features"])} features...')
start = time.time()
import pandas as pd
df = pd.DataFrame(record['features'])
print(f'[4] Done in {time.time()-start:.2f}s - Shape: {df.shape}')
print(f'    Columns: {df.columns.tolist()[:10]}...')

print(f'[5] Transforming features...')
start = time.time()
try:
    X = preprocessor.transform(df)
    print(f'[5] Done in {time.time()-start:.2f}s - Shape: {X.shape}')
except Exception as e:
    print(f'[5] ❌ ERROR: {str(e)[:200]}')
    import traceback
    traceback.print_exc()
    sys.exit(1)

print(f'[6] Running predictions...')
start = time.time()
try:
    results = classifier.predict_with_details(X)
    print(f'[6] Done in {time.time()-start:.2f}s - Results: {len(results)}')
except Exception as e:
    print(f'[6] ❌ ERROR: {str(e)[:200]}')
    sys.exit(1)

print(f'[7] Generating explanations...')
start = time.time()
try:
    from xai.explainer import explain_batch
    explanations = explain_batch(classifier, X)
    print(f'[7] Done in {time.time()-start:.2f}s - Explanations: {len(explanations)}')
except Exception as e:
    print(f'[7] ❌ ERROR: {str(e)[:200]}')
    sys.exit(1)

print('[SUCCESS] Full prediction pipeline works!')
