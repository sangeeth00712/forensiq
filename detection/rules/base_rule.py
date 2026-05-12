# detection/rules/base_rule.py
# ─────────────────────────────────────────────────────────────
# ForensiQ — Abstract Base Class for Detection Rules
#
# All detection rules inherit from this base class.
# Ensures consistent interface and behavior.
#
# Author  : Sangeeth
# Version : 1.0.0
# ─────────────────────────────────────────────────────────────

from abc import ABC, abstractmethod
from typing import List

from core.logger import get_logger
from core.models import Finding, Flow

logger = get_logger(__name__)


class BaseRule(ABC):
    """
    Abstract base class for all detection rules.
    
    Design:
    - Each rule analyzes a list of flows
    - Returns a list of Finding objects
    - Each Finding includes evidence (raw data that triggered alert)
    
    Example:
        class PortScanRule(BaseRule):
            def detect(self, flows: List[Flow]) -> List[Finding]:
                findings = []
                # Analyze flows...
                if suspicious_pattern_found:
                    findings.append(Finding(...))
                return findings
    """

    @property
    @abstractmethod
    def rule_name(self) -> str:
        """
        Unique identifier for this rule.
        
        Returns:
            Rule name (e.g. "PORT_SCAN_DETECTED")
        """
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """
        Human-readable description of what this rule detects.
        
        Returns:
            Description (e.g. "Detects network port scanning activity")
        """
        pass

    @abstractmethod
    def detect(self, flows: List[Flow]) -> List[Finding]:
        """
        Analyzes flows and returns any findings.
        
        This is the main method that subclasses implement.
        
        Args:
            flows: List of Flow objects to analyze
        
        Returns:
            List of Finding objects (empty if no threats detected)
        """
        pass

    def execute(self, flows: List[Flow]) -> List[Finding]:
        """
        Executes the detection rule with logging.
        
        This wrapper handles logging and error handling.
        Subclasses implement detect() instead.
        
        Args:
            flows: List of flows to analyze
        
        Returns:
            List of findings
        """
        logger.debug(f"Running rule: {self.rule_name}")
        
        try:
            findings = self.detect(flows)
            
            if findings:
                logger.info(
                    f"Rule {self.rule_name} found {len(findings)} "
                    f"threat(s)"
                )
            
            return findings
        
        except Exception as e:
            logger.error(f"Rule {self.rule_name} failed: {e}")
            return []  # Return empty list on error, don't crash
