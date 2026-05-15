from typing import List
from core.logger import get_logger
from core.models import Finding, Flow
from detection.rules.port_scan import PortScanRule
from detection.rules.beaconing import BeaconingRule
from detection.rules.dns_tunnel import DNSTunnelingRule
from detection.rules.exfiltration import ExfiltrationRule
from detection.rules.brute_force import BruteForceRule
from ml.anomaly import AnomalyDetector, ConfidenceScorer

logger = get_logger(__name__)


class DetectionEngine:
    """Orchestrates detection rules with ML confidence scoring."""

    def __init__(self):
        self.rules = [
            PortScanRule(),
            BeaconingRule(),
            DNSTunnelingRule(),
            ExfiltrationRule(),
            BruteForceRule(),
        ]
        self.anomaly_detector = AnomalyDetector(contamination=0.1)
        self.confidence_scorer = ConfidenceScorer(self.anomaly_detector)
        logger.info(f"Detection engine initialized with {len(self.rules)} rules")

    def run(self, flows: List[Flow]) -> List[Finding]:
        """
        Runs all detection rules with ML confidence scoring.
        
        Args:
            flows: List of flows to analyze
        
        Returns:
            List of findings with confidence scores
        """
        all_findings = []
        
        logger.info(f"Running {len(self.rules)} rules on {len(flows)} flows")

        # Fit anomaly detector on all flows
        try:
            self.anomaly_detector.fit(flows)
        except Exception as e:
            logger.warning(f"Failed to fit anomaly detector: {e}")

        # Run detection rules
        for rule in self.rules:
            findings = rule.execute(flows)
            all_findings.extend(findings)

        # Score confidence for each finding
        for finding in all_findings:
            try:
                # Get flows involved in this finding
                involved_flows = [
                    f for f in flows
                    if f.src_ip == finding.src_ip or f.dst_ip == finding.dst_ip
                ]
                
                # Score confidence
                confidence = self.confidence_scorer.score_finding(
                    finding, involved_flows
                )
                finding.confidence = confidence
                
                logger.debug(
                    f"{finding.rule_name} confidence: {confidence:.2f}"
                )
            except Exception as e:
                logger.warning(f"Failed to score {finding.rule_name}: {e}")
                finding.confidence = 0.5

        logger.info(f"Detection complete: {len(all_findings)} findings")
        return all_findings
