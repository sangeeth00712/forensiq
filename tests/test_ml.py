import pytest
from datetime import datetime, timedelta

from core.models import Flow, Protocol
from ml.features import FeatureExtractor
from ml.anomaly import AnomalyDetector, ConfidenceScorer


@pytest.fixture
def sample_flows():
    """Creates sample flows for ML training."""
    flows = []
    base_time = datetime.now()
    
    # Normal flows
    for i in range(10):
        flows.append(Flow(
            src_ip="192.168.1." + str(i),
            dst_ip="8.8.8.8",
            src_port=50000 + i,
            dst_port=80,
            protocol=Protocol.TCP,
            first_seen=base_time,
            last_seen=base_time + timedelta(seconds=5),
            packet_count=10,
            bytes_transferred=5000,
        ))
    
    return flows


class TestFeatureExtractor:
    
    def test_extract_flow_features(self, sample_flows):
        flow = sample_flows[0]
        features = FeatureExtractor.extract_flow_features(flow)
        
        assert "packet_count" in features
        assert "bytes_transferred" in features
        assert "duration_seconds" in features
        assert features["packet_count"] == 10.0

    def test_extract_group_features(self, sample_flows):
        features = FeatureExtractor.extract_group_features(sample_flows)
        
        assert "flow_count" in features
        assert "total_packets" in features
        assert features["flow_count"] == len(sample_flows)


class TestAnomalyDetector:
    
    def test_detector_initialization(self):
        detector = AnomalyDetector()
        assert not detector.is_fitted

    def test_detector_fit(self, sample_flows):
        detector = AnomalyDetector()
        detector.fit(sample_flows)
        assert detector.is_fitted

    def test_detector_score(self, sample_flows):
        detector = AnomalyDetector()
        detector.fit(sample_flows)
        
        score = detector.score(sample_flows[0])
        assert 0.0 <= score <= 1.0

    def test_detector_score_group(self, sample_flows):
        detector = AnomalyDetector()
        detector.fit(sample_flows)
        
        score = detector.score_group(sample_flows[:3])
        assert 0.0 <= score <= 1.0


class TestConfidenceScorer:
    
    def test_scorer_initialization(self, sample_flows):
        detector = AnomalyDetector()
        detector.fit(sample_flows)
        scorer = ConfidenceScorer(detector)
        
        assert scorer.detector is not None
