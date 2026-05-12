# detection/rules/brute_force.py
# ─────────────────────────────────────────────────────────────
# ForensiQ — Brute Force Detection Rule
#
# Detects repeated failed authentication attempts.
#
# Author  : Sangeeth
# Version : 1.0.0
# ─────────────────────────────────────────────────────────────

from collections import defaultdict
from typing import List

import config
from core.logger import get_logger
from core.models import Finding, Flow, Severity, RuleCategory, IOC, IOCType
from detection.rules.base_rule import BaseRule

logger = get_logger(__name__)


class BruteForceRule(BaseRule):
    """
    Detects brute force attacks (repeated failed authentication).
    
    Pattern:
    - 20+ failed auth attempts
    - To same service (same port)
    - From same source IP
    - Within 60 seconds
    
    Services targeted:
    - SSH (port 22) — most common
    - FTP (port 21)
    - HTTP/HTTPS (port 80/443)
    - RDP (port 3389)
    
    MITRE ATT&CK: T1110 (Brute Force)
    """

    @property
    def rule_name(self) -> str:
        return "BRUTE_FORCE_DETECTED"

    @property
    def description(self) -> str:
        return "Detects brute force password guessing attacks"

    def detect(self, flows: List[Flow]) -> List[Finding]:
        """
        Analyzes flows for brute force patterns.
        
        Algorithm:
        1. Look for many short connections (typical of failed auth attempts)
        2. Same source → same destination port
        3. Within short time window
        
        Args:
            flows: List of flows to analyze
        
        Returns:
            List of Finding objects
        """
        findings = []

        # Group by source IP, destination IP, and port
        brute_force_candidates = defaultdict(list)

        for flow in flows:
            # Only TCP flows
            if flow.protocol.value != "TCP":
                continue

            key = (flow.src_ip, flow.dst_ip, flow.dst_port)
            brute_force_candidates[key].append(flow)

        # Analyze each candidate
        for (src_ip, dst_ip, dst_port), flows_list in brute_force_candidates.items():
            # Check connection count
            if len(flows_list) < config.BRUTE_FORCE_THRESHOLD:
                continue

            # Sort by timestamp
            flows_list.sort(key=lambda f: f.first_seen)

            # Check time window
            duration = (flows_list[-1].last_seen - flows_list[0].first_seen).total_seconds()
            if duration > config.BRUTE_FORCE_WINDOW_SECONDS:
                continue

            # All conditions met — this is brute force
            service_name = self._identify_service(dst_port)

            logger.info(
                f"Brute force detected: {src_ip} → {dst_ip}:{dst_port} "
                f"({len(flows_list)} attempts in {duration:.0f}s, {service_name})"
            )

            finding = Finding(
                rule_name=self.rule_name,
                severity=Severity.HIGH,
                category=RuleCategory.LATERAL_MOVEMENT,
                title=f"Brute Force Attack: {src_ip} → {dst_ip}:{dst_port}",
                description=(
                    f"Host {src_ip} made {len(flows_list)} rapid connection "
                    f"attempts to {dst_ip}:{dst_port} ({service_name}) in "
                    f"{duration:.0f} seconds. This is consistent with a "
                    f"password guessing attack."
                ),
                evidence={
                    "source_ip": src_ip,
                    "destination_ip": dst_ip,
                    "target_port": dst_port,
                    "service": service_name,
                    "attempt_count": len(flows_list),
                    "duration_seconds": duration,
                    "attempts_per_second": round(len(flows_list) / duration, 2) if duration > 0 else 0,
                },
                src_ip=src_ip,
                dst_ip=dst_ip,
                timestamp=flows_list[0].first_seen,
                mitre_technique="T1110",
                mitre_tactic="Credential Access",
            )

            finding.iocs.append(IOC(value=src_ip, ioc_type=IOCType.IP))
            finding.iocs.append(IOC(value=dst_ip, ioc_type=IOCType.IP))

            findings.append(finding)

        return findings

    @staticmethod
    def _identify_service(port: int) -> str:
        """
        Identifies service by port number.
        
        Args:
            port: Port number
        
        Returns:
            Service name
        """
        services = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            80: "HTTP",
            443: "HTTPS",
            3389: "RDP",
            5432: "PostgreSQL",
            3306: "MySQL",
            1433: "MSSQL",
        }
        return services.get(port, f"Unknown (port {port})")
