"""
BENFET ML - Model Manager (Single Model)
Always saves/loads a single model. No versioning — one trained model at a time.
"""

import os
import pickle
import json
import shutil
from datetime import datetime
from config import MODELS_FOLDER

# Fixed paths — always the same single model
MODEL_DIR = os.path.join(MODELS_FOLDER, 'current')
CLASSIFIER_PATH = os.path.join(MODEL_DIR, 'classifier.pkl')
SCALER_PATH = os.path.join(MODEL_DIR, 'scaler.pkl')
META_PATH = os.path.join(MODEL_DIR, 'metadata.json')


def save_model(classifier, preprocessor, name=None, metadata=None):
    """
    Save the classifier and preprocessor as the ONE active model.
    Overwrites any previously saved model.
    """
    # Clean old model directory and recreate
    if os.path.exists(MODEL_DIR):
        shutil.rmtree(MODEL_DIR)
    os.makedirs(MODEL_DIR, exist_ok=True)

    # Save classifier
    classifier.save(CLASSIFIER_PATH)

    # Save preprocessor
    preprocessor.save(SCALER_PATH)

    # Save metadata
    meta = {
        'name': 'benfet_model',
        'created_at': datetime.now().isoformat(),
        'class_labels': classifier.class_labels,
        'is_trained': classifier.is_trained,
    }
    if metadata:
        meta.update(metadata)

    with open(META_PATH, 'w') as f:
        json.dump(meta, f, indent=2)

    return MODEL_DIR


def load_model(name=None):
    """
    Load the single saved model.

    Returns:
        tuple: (BehavioralClassifier, Preprocessor, metadata_dict)
    """
    from ml.classifier import BehavioralClassifier
    from ml.preprocessor import Preprocessor

    if not os.path.exists(CLASSIFIER_PATH):
        raise FileNotFoundError(
            "No trained model found. Click '🧠 Train Model' first."
        )

    classifier = BehavioralClassifier()
    classifier.load(CLASSIFIER_PATH)

    preprocessor = Preprocessor()
    preprocessor.load(SCALER_PATH)

    metadata = {}
    if os.path.exists(META_PATH):
        with open(META_PATH, 'r') as f:
            metadata = json.load(f)

    return classifier, preprocessor, metadata


def model_exists():
    """Check if a trained model exists."""
    return os.path.exists(CLASSIFIER_PATH)


def get_model_info():
    """Get metadata about the current model, or None."""
    if not os.path.exists(META_PATH):
        return None
    with open(META_PATH, 'r') as f:
        return json.load(f)


def delete_model():
    """Delete the current model."""
    if os.path.exists(MODEL_DIR):
        shutil.rmtree(MODEL_DIR)
        return True
    return False


# Keep for API compatibility — returns a list with 0 or 1 model
def list_models():
    info = get_model_info()
    return [info] if info else []


class ModelManager:
    """
    Wrapper class for model management.
    Provides class-based interface to module-level functions.
    Always manages a single model (no versioning).
    """

    @staticmethod
    def save(classifier, preprocessor, name=None, metadata=None):
        """Save the classifier and preprocessor as the ONE active model."""
        return save_model(classifier, preprocessor, name, metadata)

    @staticmethod
    def load(name=None):
        """Load the single saved model.
        Returns: tuple (BehavioralClassifier, Preprocessor, metadata_dict)
        """
        return load_model(name)

    @staticmethod
    def exists():
        """Check if a trained model exists."""
        return model_exists()

    @staticmethod
    def get_info():
        """Get metadata about the current model, or None."""
        return get_model_info()

    @staticmethod
    def delete():
        """Delete the current model."""
        return delete_model()

    @staticmethod
    def list_all():
        """List all saved models (always 0 or 1)."""
        return list_models()
