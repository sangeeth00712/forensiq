# detection/rules/dns_tunnel.py
# ─────────────────────────────────────────────────────────────
# ForensiQ — DNS Tunneling Detection Rule
#
# Detects DNS being used for data exfiltration or command issuance.
#
# Author  : Sangeeth
# Version : 1.0.0
# ─────────────────────────────────────────────────────────────

from collections import defaultdict
from math import log2
from typing import List

import config
from core.logger import get_logger
from core.models import Finding, Flow, Severity, RuleCategory, IOC, IOCType
from detection.rules.base_rule import BaseRule

logger = get_logger(__name__)


class DNSTunnelingRule(BaseRule):
    """
    Detects DNS tunneling (data exfiltration via DNS).
    
    Pattern:
    - Unusually long DNS query names
    - High entropy (randomness) in query
    - Unusual query frequency
    
    MITRE ATT&CK: T1071.004 (Application Layer Protocol — DNS)
    """

    @property
    def rule_name(self) -> str:
        return "DNS_TUNNELING_DETECTED"

    @property
    def description(self) -> str:
        return "Detects DNS tunneling (data exfiltration via DNS)"

    def _calculate_entropy(self, data: str) -> float:
        """
        Calculates Shannon entropy of a string.
        
        Entropy measures randomness:
        - Low entropy (1-2): Normal words (predictable)
        - High entropy (3.5+): Random data (suspicious)
        
        Args:
            data: String to calculate entropy for
        
        Returns:
            Shannon entropy value (0.0-8.0)
        """
        if not data:
            return 0.0

        # Count frequency of each character
        frequencies = {}
        for char in data.lower():
            frequencies[char] = frequencies.get(char, 0) + 1

        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        for count in frequencies.values():
            probability = count / data_len
            entropy -= probability * log2(probability)

        return entropy

    def detect(self, flows: List[Flow]) -> List[Finding]:
        """
        Analyzes flows for DNS tunneling.
        
        Algorithm:
        1. Find flows with DNS queries
        2. Calculate entropy of query names
        3. Check for suspicious patterns:
           - Long subdomain names (>52 chars)
           - High entropy (>3.5)
           - High query frequency
        4. Flag combinations as tunneling
        
        Args:
            flows: List of flows to analyze
        
        Returns:
            List of Finding objects
        """
        findings = []

        # Group DNS flows by source IP
        dns_flows = defaultdict(list)

        for flow in flows:
            if flow.dns_query and flow.protocol.value == "DNS":
                dns_flows[flow.src_ip].append(flow)

        # Analyze each source
        for src_ip, flows_list in dns_flows.items():
            suspicious_queries = []

            for flow in flows_list:
                if not flow.dns_query:
                    continue

                # Extract subdomain (first part before domain)
                parts = flow.dns_query.split('.')
                if len(parts) > 0:
                    subdomain = parts[0]
                else:
                    subdomain = flow.dns_query

                # Check characteristics
                query_len = len(subdomain)
                entropy = self._calculate_entropy(subdomain)

                is_suspicious = (
                    query_len > config.DNS_TUNNEL_LABEL_LENGTH
                    or entropy > config.DNS_TUNNEL_MIN_ENTROPY
                )

                if is_suspicious:
                    suspicious_queries.append({
                        "query": flow.dns_query,
                        "subdomain": subdomain,
                        "length": query_len,
                        "entropy": entropy,
                    })

            # Check if this is tunneling
            if len(suspicious_queries) >= 3:  # Multiple suspicious queries
                logger.info(
                    f"DNS tunneling detected: {src_ip} "
                    f"({len(suspicious_queries)} suspicious queries)"
                )

                finding = Finding(
                    rule_name=self.rule_name,
                    severity=Severity.HIGH,
                    category=RuleCategory.EXFILTRATION,
                    title=f"DNS Tunneling: {src_ip}",
                    description=(
                        f"Host {src_ip} issued {len(suspicious_queries)} DNS queries "
                        f"with suspicious characteristics (long names, high entropy). "
                        f"This pattern is consistent with DNS tunneling used for "
                        f"data exfiltration or command & control."
                    ),
                    evidence={
                        "source_ip": src_ip,
                        "suspicious_query_count": len(suspicious_queries),
                        "sample_queries": [
                            {
                                "query": q["query"],
                                "entropy": round(q["entropy"], 2),
                                "length": q["length"],
                            }
                            for q in suspicious_queries[:5]
                        ],
                    },
                    src_ip=src_ip,
                    dst_ip="unknown",
                    timestamp=flows_list[0].first_seen,
                    mitre_technique="T1071.004",
                    mitre_tactic="Command and Control",
                )

                finding.iocs.append(IOC(value=src_ip, ioc_type=IOCType.IP))
                findings.append(finding)

        return findings
