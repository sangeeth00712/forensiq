from typing import List
from core.logger import get_logger
from core.models import Finding, Flow
from detection.rules.port_scan import PortScanRule
from detection.rules.beaconing import BeaconingRule
from detection.rules.dns_tunnel import DNSTunnelingRule
from detection.rules.exfiltration import ExfiltrationRule
from detection.rules.brute_force import BruteForceRule

logger = get_logger(__name__)


class DetectionEngine:
    """Orchestrates all detection rules."""

    def __init__(self):
        self.rules = [
            PortScanRule(),
            BeaconingRule(),
            DNSTunnelingRule(),
            ExfiltrationRule(),
            BruteForceRule(),
        ]
        logger.info(f"Detection engine initialized with {len(self.rules)} rules")

    def run(self, flows: List[Flow]) -> List[Finding]:
        """
        Runs all detection rules against flows.

        Args:
            flows: List of flows to analyze

        Returns:
            Combined list of all findings
        """
        all_findings = []
        logger.info(f"Running {len(self.rules)} rules on {len(flows)} flows")

        for rule in self.rules:
            findings = rule.execute(flows)
            all_findings.extend(findings)

        logger.info(f"Detection complete: {len(all_findings)} total findings")
        return all_findings
