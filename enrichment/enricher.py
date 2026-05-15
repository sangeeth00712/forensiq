from typing import List
import ipaddress

from core.logger import get_logger
from core.models import Finding, IOC, IOCType
from enrichment.cache import EnrichmentCache
from enrichment.virustotal import VirusTotalClient
from enrichment.mitre import MITREMapping
import config

logger = get_logger(__name__)


class Enricher:
    """
    Enriches findings with threat intelligence.
    
    Process:
    1. Extract IOCs from findings
    2. Check cache (24hr TTL)
    3. If not cached, query VirusTotal
    4. Add MITRE ATT&CK mapping
    5. Update finding with enriched data
    """

    def __init__(self):
        self.cache = EnrichmentCache()
        self.vt = VirusTotalClient()
        logger.info("Enricher initialized")

    def _is_private_ip(self, ip: str) -> bool:
        """
        Checks if IP is private (never send to external APIs).
        
        Args:
            ip: IP address string
        
        Returns:
            True if private
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except ValueError:
            return False

    def enrich_ioc(self, ioc: IOC) -> None:
        """
        Enriches a single IOC.
        
        Args:
            ioc: IOC object (mutated in place)
        """
        # Check cache first
        cached = self.cache.get(ioc.value)
        if cached:
            ioc.malicious = cached.get("malicious", False)
            ioc.vt_score = cached.get("vt_score")
            ioc.country = cached.get("country")
            ioc.asn = cached.get("asn")
            ioc.enriched = True
            return

        # Skip private IPs (SSRF prevention)
        if self._is_private_ip(ioc.value):
            logger.debug(f"Skipping private IP: {ioc.value}")
            ioc.enriched = True
            return

        # Query VirusTotal
        if ioc.ioc_type == IOCType.IP:
            vt_data = self.vt.lookup_ip(ioc.value)
        elif ioc.ioc_type == IOCType.DOMAIN:
            vt_data = self.vt.lookup_domain(ioc.value)
        else:
            vt_data = None

        if vt_data:
            ioc.malicious = vt_data.get("malicious", False)
            ioc.vt_score = vt_data.get("vt_score")
            ioc.country = vt_data.get("country")
            ioc.asn = vt_data.get("asn")
            ioc.enriched = True
            
            # Cache result
            self.cache.set(ioc.value, ioc.ioc_type.value, vt_data)
        else:
            ioc.enriched = True  # Mark as attempted

    def enrich_finding(self, finding: Finding) -> None:
        """
        Enriches all IOCs in a finding.
        
        Args:
            finding: Finding object (mutated in place)
        """
        # Enrich each IOC
        for ioc in finding.iocs:
            self.enrich_ioc(ioc)

        # Add MITRE details if not already there
        if finding.mitre_technique:
            tech_data = MITREMapping.get_technique(finding.mitre_technique)
            if tech_data:
                finding.mitre_tactic = tech_data.get("tactic", finding.mitre_tactic)

    def enrich_all(self, findings: List[Finding]) -> List[Finding]:
        """
        Enriches all findings.
        
        Args:
            findings: List of findings
        
        Returns:
            Same list (mutated in place)
        """
        logger.info(f"Enriching {len(findings)} findings")

        for finding in findings:
            try:
                self.enrich_finding(finding)
            except Exception as e:
                logger.error(f"Enrichment failed for {finding.rule_name}: {e}")

        logger.info("Enrichment complete")
        return findings
