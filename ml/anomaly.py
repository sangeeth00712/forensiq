from typing import List, Dict, Tuple
import numpy as np
from sklearn.ensemble import IsolationForest

from core.logger import get_logger
from core.models import Flow, Finding
from ml.features import FeatureExtractor

logger = get_logger(__name__)


class AnomalyDetector:
    """
    Uses Isolation Forest to detect anomalous flows.
    
    Isolation Forest works by:
    1. Randomly selecting features
    2. Randomly selecting split values
    3. Isolating anomalies faster than normal points
    4. Scoring: -1 (anomaly) to 0 (normal)
    """

    def __init__(self, contamination: float = 0.1):
        """
        Initialize anomaly detector.
        
        Args:
            contamination: Expected fraction of anomalies (0.1 = 10%)
        """
        self.model = IsolationForest(
            contamination=contamination,
            random_state=42,
        )
        self.feature_names = None
        self.is_fitted = False
        logger.debug("AnomalyDetector initialized")

    def fit(self, flows: List[Flow]) -> None:
        """
        Trains model on normal flows.
        
        Args:
            flows: List of flows (assumed mostly normal)
        """
        if not flows:
            logger.warning("No flows to fit on")
            return

        # Extract features
        features_list = []
        for flow in flows:
            features = FeatureExtractor.extract_flow_features(flow)
            features_list.append(features)

        # Convert to numpy array
        feature_names = list(features_list[0].keys())
        self.feature_names = feature_names
        
        X = np.array([[f[name] for name in feature_names] for f in features_list])

        # Fit model
        self.model.fit(X)
        self.is_fitted = True

        logger.info(f"AnomalyDetector fitted on {len(flows)} flows")

    def score(self, flow: Flow) -> float:
        """
        Scores a flow for anomaly.
        
        Returns:
            Score from 0.0 (normal) to 1.0 (very anomalous)
        """
        if not self.is_fitted:
            logger.warning("Model not fitted yet")
            return 0.5

        features = FeatureExtractor.extract_flow_features(flow)
        X = np.array([[features[name] for name in self.feature_names]])

        # Isolation Forest returns anomaly score (-1 to 0)
        # Convert to 0-1 scale
        raw_score = self.model.score_samples(X)[0]
        
        # Normalize: -1 (anomaly) → 1.0, 0 (normal) → 0.0
        normalized_score = (raw_score + 1) / 2
        
        return float(max(0.0, min(1.0, normalized_score)))

    def score_group(self, flows: List[Flow]) -> float:
        """
        Scores a group of flows (for findings).
        
        Args:
            flows: List of flows
        
        Returns:
            Anomaly score 0.0-1.0
        """
        if not flows:
            return 0.0

        # Score individual flows and average
        scores = [self.score(flow) for flow in flows]
        return float(np.mean(scores))


class ConfidenceScorer:
    """
    Scores finding confidence using multiple signals.
    
    Combines:
    - ML anomaly score
    - Rule severity (higher severity = more confidence)
    - Evidence quality (more evidence = more confidence)
    """

    def __init__(self, anomaly_detector: AnomalyDetector):
        """Initialize with anomaly detector."""
        self.detector = anomaly_detector

    def score_finding(self, finding: Finding, flows: List[Flow]) -> float:
        """
        Scores a finding's confidence.
        
        Args:
            finding: Finding object
            flows: Flows involved in finding
        
        Returns:
            Confidence 0.0-1.0
        """
        if not flows:
            return 0.5

        # Get ML anomaly score
        ml_score = self.detector.score_group(flows)

        # Rule severity bonus
        severity_bonus = {
            "LOW": 0.6,
            "MEDIUM": 0.75,
            "HIGH": 0.85,
            "CRITICAL": 0.95,
        }
        severity_score = severity_bonus.get(finding.severity.value, 0.5)

        # Evidence quality (more evidence = more confidence)
        evidence_count = len(finding.evidence)
        evidence_score = min(0.95, 0.5 + (evidence_count * 0.1))

        # Combine signals (weighted average)
        final_score = (
            0.5 * ml_score +       # 50% from ML model
            0.3 * severity_score + # 30% from rule severity
            0.2 * evidence_score   # 20% from evidence quality
        )

        return float(max(0.0, min(1.0, final_score)))
