from typing import Dict, Optional

from core.logger import get_logger

logger = get_logger(__name__)


class MITREMapping:
    """
    MITRE ATT&CK technique and tactic mapping.
    
    Hardcoded dict (not API call) for offline operation.
    """

    TECHNIQUES = {
        "T1046": {
            "tactic": "Discovery",
            "name": "Network Service Discovery",
            "description": "Adversaries may attempt to get a listing of services running on remote hosts.",
        },
        "T1071": {
            "tactic": "Command and Control",
            "name": "Application Layer Protocol",
            "description": "Adversaries may communicate using application layer protocols.",
        },
        "T1071.004": {
            "tactic": "Command and Control",
            "name": "DNS",
            "description": "Adversaries may communicate over the DNS protocol.",
        },
        "T1020": {
            "tactic": "Impact",
            "name": "Data Transfer Out",
            "description": "An adversary may exfiltrate data.",
        },
        "T1110": {
            "tactic": "Credential Access",
            "name": "Brute Force",
            "description": "Adversaries use brute force techniques to gain access.",
        },
    }

    @classmethod
    def get_technique(cls, technique_id: str) -> Optional[Dict]:
        """
        Gets MITRE technique details.
        
        Args:
            technique_id: Technique ID (e.g. "T1046")
        
        Returns:
            Technique dict or None
        """
        return cls.TECHNIQUES.get(technique_id)

    @classmethod
    def get_tactic(cls, technique_id: str) -> Optional[str]:
        """Gets tactic for a technique."""
        tech = cls.get_technique(technique_id)
        return tech["tactic"] if tech else None

    @classmethod
    def all_techniques(cls) -> Dict:
        """Returns all techniques."""
        return cls.TECHNIQUES
