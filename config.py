import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Upload configuration
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
ALLOWED_EXTENSIONS = {'pcap', 'pcapng', 'cap'}
MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100 MB max upload

# Model storage
MODELS_FOLDER = os.path.join(BASE_DIR, 'models')
DEFAULT_MODEL_NAME = 'rf_behavioral_model.pkl'
DEFAULT_SCALER_NAME = 'scaler.pkl'

# Reports
REPORTS_FOLDER = os.path.join(BASE_DIR, 'reports', 'generated')
REPORT_TEMPLATE_DIR = os.path.join(BASE_DIR, 'reports', 'templates')

# Dataset
DATASET_FOLDER = os.path.join(BASE_DIR, 'datasets')

# Analysis results cache
ANALYSIS_FOLDER = os.path.join(BASE_DIR, 'analysis_cache')

# Feature extraction parameters
BURST_THRESHOLD_SECONDS = 0.1   # Max inter-arrival time within a burst
MIN_BURST_PACKETS = 3           # Minimum packets to qualify as a burst
FLOW_TIMEOUT_SECONDS = 120      # Timeout for flow grouping

# Ensure directories exist
for folder in [UPLOAD_FOLDER, MODELS_FOLDER, REPORTS_FOLDER, DATASET_FOLDER, ANALYSIS_FOLDER]:
    os.makedirs(folder, exist_ok=True)
