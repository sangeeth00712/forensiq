from typing import List, Dict
import statistics

from core.logger import get_logger
from core.models import Flow

logger = get_logger(__name__)


class FeatureExtractor:
    """
    Extracts statistical features from flows for ML analysis.
    
    Features measure:
    - Volume (bytes, packets)
    - Timing (intervals, duration)
    - Protocol characteristics
    """

    @staticmethod
    def extract_flow_features(flow: Flow) -> Dict[str, float]:
        """
        Extracts features from a single flow.
        
        Args:
            flow: Flow object
        
        Returns:
            Dictionary of feature name → value
        """
        features = {
            "packet_count": float(flow.packet_count),
            "bytes_transferred": float(flow.bytes_transferred),
            "duration_seconds": flow.duration_seconds,
            "bytes_per_second": flow.bytes_per_second,
            "port_number": float(flow.dst_port),
        }
        
        return features

    @staticmethod
    def extract_group_features(flows: List[Flow]) -> Dict[str, float]:
        """
        Extracts aggregate features from multiple flows.
        
        Args:
            flows: List of Flow objects
        
        Returns:
            Dictionary of aggregate feature name → value
        """
        if not flows:
            return {}

        packet_counts = [f.packet_count for f in flows]
        byte_counts = [f.bytes_transferred for f in flows]
        durations = [f.duration_seconds for f in flows]
        ports = [f.dst_port for f in flows]

        features = {
            "flow_count": float(len(flows)),
            "total_packets": float(sum(packet_counts)),
            "total_bytes": float(sum(byte_counts)),
            "avg_packet_count": statistics.mean(packet_counts),
            "avg_bytes": statistics.mean(byte_counts),
            "avg_duration": statistics.mean(durations) if durations else 0.0,
            "unique_ports": float(len(set(ports))),
            "min_port": float(min(ports)) if ports else 0.0,
            "max_port": float(max(ports)) if ports else 0.0,
        }

        # Add variance if multiple flows
        if len(flows) > 1:
            features["packet_variance"] = statistics.variance(packet_counts)
            features["bytes_variance"] = statistics.variance(byte_counts)
        else:
            features["packet_variance"] = 0.0
            features["bytes_variance"] = 0.0

        return features
