"""
BENFET ML - Behavioral Classifier
Random Forest classifier for user attribution and fingerprinting.
Provides predictions with confidence scores and feature importances.
"""

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score
from sklearn.metrics import classification_report, confusion_matrix
import pickle
import os
from config import MODELS_FOLDER, DEFAULT_MODEL_NAME


class BehavioralClassifier:
    """Random Forest classifier for behavioral fingerprinting."""

    def __init__(self, n_estimators=100, max_depth=None, random_state=42):
        self.model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            random_state=random_state,
            n_jobs=-1,
            class_weight='balanced',
        )
        self.is_trained = False
        self.class_labels = None

    def train(self, X, y):
        """
        Train the classifier on feature vectors.

        Args:
            X: numpy array of shape (n_samples, n_features)
            y: numpy array of labels

        Returns:
            dict with training metrics
        """
        self.model.fit(X, y)
        self.is_trained = True
        self.class_labels = list(self.model.classes_)

        # Training accuracy
        train_accuracy = self.model.score(X, y)

        # Cross-validation
        cv_scores = cross_val_score(self.model, X, y, cv=min(5, len(set(y))), scoring='accuracy')

        return {
            'train_accuracy': round(train_accuracy, 4),
            'cv_mean_accuracy': round(cv_scores.mean(), 4),
            'cv_std': round(cv_scores.std(), 4),
            'n_samples': len(y),
            'n_classes': len(set(y)),
            'class_labels': self.class_labels,
        }

    def predict(self, X):
        """
        Predict user labels with confidence scores.

        Args:
            X: numpy array of feature vectors

        Returns:
            predictions: list of predicted labels
            confidences: list of confidence scores (max probability)
        """
        if not self.is_trained:
            raise RuntimeError("Model not trained. Call train() first or load a saved model.")

        predictions = self.model.predict(X)
        probabilities = self.model.predict_proba(X)
        confidences = np.max(probabilities, axis=1)

        return predictions.tolist(), confidences.tolist()

    def predict_with_details(self, X):
        """
        Predict with full probability breakdown per class.

        Args:
            X: numpy array of feature vectors

        Returns:
            list of dicts with prediction details per sample
        """
        if not self.is_trained:
            raise RuntimeError("Model not trained.")

        predictions = self.model.predict(X)
        probabilities = self.model.predict_proba(X)

        results = []
        for i in range(len(X)):
            prob_dict = {
                label: round(float(prob), 4)
                for label, prob in zip(self.class_labels, probabilities[i])
            }
            
            pred_label = str(predictions[i])
            is_vpn = "vpn" in pred_label.lower()
            
            malicious_keywords = ["malware", "ransomware", "brute_force", "apt", "ddos", "botnet", "cryptominer"]
            is_malicious = any(kw in pred_label.lower() for kw in malicious_keywords)
            
            threat_type = pred_label.replace("vpn_", "").replace("_", " ").title() if is_malicious else "Safe Traffic"
            category = "Malicious" if is_malicious else "Normal"

            results.append({
                'prediction': pred_label,
                'confidence': round(float(np.max(probabilities[i])), 4),
                'probabilities': prob_dict,
                'category': category,
                'is_vpn': is_vpn,
                'is_malicious': is_malicious,
                'threat_type': threat_type,
            })

        return results

    def get_feature_importances(self, feature_names=None):
        """
        Get feature importance rankings from the trained model.

        Args:
            feature_names: list of feature names (optional)

        Returns:
            list of (feature_name, importance) tuples sorted by importance
        """
        if not self.is_trained:
            raise RuntimeError("Model not trained.")

        importances = self.model.feature_importances_
        if feature_names is None:
            feature_names = [f'feature_{i}' for i in range(len(importances))]

        pairs = list(zip(feature_names, importances.tolist()))
        return sorted(pairs, key=lambda x: x[1], reverse=True)

    def evaluate(self, X, y):
        """
        Evaluate model on test data.

        Returns:
            dict with accuracy, classification report, confusion matrix
        """
        if not self.is_trained:
            raise RuntimeError("Model not trained.")

        predictions = self.model.predict(X)
        accuracy = self.model.score(X, y)

        return {
            'accuracy': round(accuracy, 4),
            'report': classification_report(y, predictions, output_dict=True),
            'confusion_matrix': confusion_matrix(y, predictions).tolist(),
        }

    def save(self, path=None):
        """Save trained model to disk."""
        if path is None:
            path = os.path.join(MODELS_FOLDER, DEFAULT_MODEL_NAME)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'wb') as f:
            pickle.dump({
                'model': self.model,
                'class_labels': self.class_labels,
            }, f)

    def load(self, path=None):
        """Load a saved model from disk."""
        if path is None:
            path = os.path.join(MODELS_FOLDER, DEFAULT_MODEL_NAME)
        with open(path, 'rb') as f:
            data = pickle.load(f)
        self.model = data['model']
        self.class_labels = data['class_labels']
        self.is_trained = True
