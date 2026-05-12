# detection/rules/port_scan.py
# ─────────────────────────────────────────────────────────────
# ForensiQ — Port Scan Detection Rule
#
# Detects when a host scans multiple ports on a target.
# Indicator of network reconnaissance activity.
#
# Author  : Sangeeth
# Version : 1.0.0
# ─────────────────────────────────────────────────────────────

from collections import defaultdict
from datetime import timedelta
from typing import List

import config
from core.logger import get_logger
from core.models import Finding, Flow, Severity, RuleCategory, IOC, IOCType
from detection.rules.base_rule import BaseRule

logger = get_logger(__name__)


class PortScanRule(BaseRule):
    """
    Detects port scanning activity.
    
    Pattern:
    - One source IP
    - Connects to 15+ unique destination ports
    - On same destination IP
    - Within 60 seconds
    
    MITRE ATT&CK: T1046 (Network Service Discovery)
    """

    @property
    def rule_name(self) -> str:
        return "PORT_SCAN_DETECTED"

    @property
    def description(self) -> str:
        return "Detects network port scanning activity (reconnaissance)"

    def detect(self, flows: List[Flow]) -> List[Finding]:
        """
        Analyzes flows for port scanning behavior.
        
        Algorithm:
        1. Group flows by (src_ip, dst_ip) pair
        2. For each pair, count unique destination ports
        3. If count >= threshold AND duration <= window, flag as scan
        4. Return Finding with evidence
        
        Args:
            flows: List of flows to analyze
        
        Returns:
            List of Finding objects (empty if no scans detected)
        """
        findings = []
        
        # Group flows by source and destination IP
        scan_candidates = defaultdict(lambda: {
            "ports": set(),
            "flows": [],
            "first_time": None,
            "last_time": None,
        })

        for flow in flows:
            # Only look at TCP flows (port scanning typically TCP)
            if flow.protocol.value not in ["TCP", "OTHER"]:
                continue

            key = (flow.src_ip, flow.dst_ip)
            scan_candidates[key]["ports"].add(flow.dst_port)
            scan_candidates[key]["flows"].append(flow)

            if scan_candidates[key]["first_time"] is None:
                scan_candidates[key]["first_time"] = flow.first_seen
            scan_candidates[key]["last_time"] = flow.last_seen

        # Check each candidate for port scan pattern
        for (src_ip, dst_ip), data in scan_candidates.items():
            port_count = len(data["ports"])
            
            # Check threshold
            if port_count < config.PORT_SCAN_THRESHOLD:
                continue

            # Check time window
            duration = (data["last_time"] - data["first_time"]).total_seconds()
            if duration > config.PORT_SCAN_WINDOW_SECONDS:
                continue

            # This is a port scan!
            logger.info(
                f"Port scan detected: {src_ip} scanned {port_count} ports "
                f"on {dst_ip} in {duration:.0f} seconds"
            )

            # Create Finding with evidence
            finding = Finding(
                rule_name=self.rule_name,
                severity=Severity.HIGH,
                category=RuleCategory.RECONNAISSANCE,
                title=f"Network Port Scan: {src_ip} → {dst_ip}",
                description=(
                    f"Host {src_ip} scanned {port_count} unique ports on "
                    f"{dst_ip} in {duration:.0f} seconds. This is consistent "
                    f"with automated network reconnaissance activity."
                ),
                evidence={
                    "scanned_ports": sorted(list(data["ports"])),
                    "port_count": port_count,
                    "duration_seconds": duration,
                    "flow_count": len(data["flows"]),
                },
                src_ip=src_ip,
                dst_ip=dst_ip,
                timestamp=data["first_time"],
                mitre_technique="T1046",
                mitre_tactic="Discovery",
            )

            # Add source IP as IOC
            finding.iocs.append(IOC(
                value=src_ip,
                ioc_type=IOCType.IP,
            ))

            findings.append(finding)

        return findings
