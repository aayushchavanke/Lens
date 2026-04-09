"""
BENFET ML - Feature Weights
Provides optional weighting for behavioral features.
Currently uses uniform weights; can be extended with domain-specific weighting.
"""

import numpy as np
from ml.preprocessor import FEATURE_COLUMNS


class FeatureWeights:
    """Feature weighting for behavioral fingerprinting."""

    @staticmethod
    def get_weights_array(normalize=True):
        """
        Get a weight array for features.
        
        Args:
            normalize: if True, weights sum to 1.0
            
        Returns:
            numpy array of weights (one per feature)
        """
        # All features equally weighted
        weights = np.ones(len(FEATURE_COLUMNS))
        
        if normalize:
            weights = weights / np.sum(weights)
        
        return weights

    @staticmethod
    def apply_weights(X, weights=None):
        """
        Apply weights to feature matrix.
        
        Args:
            X: numpy array of shape (n_samples, n_features)
            weights: optional weight array; defaults to uniform
            
        Returns:
            weighted feature matrix
        """
        if weights is None:
            weights = FeatureWeights.get_weights_array(normalize=False)
        
        return X * weights
