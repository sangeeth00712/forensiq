from typing import List, Dict
from core.logger import get_logger
from core.models import Flow, Finding

logger = get_logger(__name__)


class FindingExplainer:
    """
    Explains why a finding was detected.
    
    Provides human-readable explanation of:
    - What triggered the alert
    - Which flows were involved
    - Key statistical facts
    """

    @staticmethod
    def explain(finding: Finding, flows: List[Flow]) -> str:
        """
        Generates plain English explanation of finding.
        
        Args:
            finding: Finding object
            flows: Flows involved
        
        Returns:
            Human-readable explanation
        """
        explanation = f"""
FINDING: {finding.title}
SEVERITY: {finding.severity.value}
RULE: {finding.rule_name}

WHAT HAPPENED:
{finding.description}

KEY EVIDENCE:
"""
        
        for key, value in finding.evidence.items():
            explanation += f"  • {key}: {value}\n"

        explanation += f"""
INVOLVED FLOWS: {len(flows)}
CONFIDENCE: {finding.confidence:.1%}
MITRE TECHNIQUE: {finding.mitre_technique} ({finding.mitre_tactic})

INDICATORS OF COMPROMISE:
"""
        
        for ioc in finding.iocs:
            status = "KNOWN MALICIOUS" if ioc.malicious else "UNKNOWN"
            explanation += f"  • {ioc.value} ({ioc.ioc_type.value}) — {status}\n"

        return explanation
