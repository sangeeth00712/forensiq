# detection/rules/exfiltration.py
# ─────────────────────────────────────────────────────────────
# ForensiQ — Data Exfiltration Detection Rule
#
# Detects large data transfers to external destinations.
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


class ExfiltrationRule(BaseRule):
    """
    Detects data exfiltration (large outbound transfers).
    
    Pattern:
    - Large data transfer (50MB+)
    - To external destination (unknown IP)
    - Within short time window (5 minutes)
    
    MITRE ATT&CK: T1020 (Data Transfer Out)
    """

    @property
    def rule_name(self) -> str:
        return "DATA_EXFILTRATION_DETECTED"

    @property
    def description(self) -> str:
        return "Detects large data exfiltration"

    def detect(self, flows: List[Flow]) -> List[Finding]:
        """
        Analyzes flows for data exfiltration patterns.
        
        Algorithm:
        1. For each source IP
        2. Sum bytes transferred to each destination
        3. If sum >= threshold AND duration <= window, flag as exfil
        
        Args:
            flows: List of flows to analyze
        
        Returns:
            List of Finding objects
        """
        findings = []

        # Group by source and destination
        exfil_candidates = defaultdict(lambda: {
            "destinations": defaultdict(int),
            "flows": [],
            "first_time": None,
            "last_time": None,
        })

        for flow in flows:
            key = flow.src_ip

            exfil_candidates[key]["destinations"][flow.dst_ip] += flow.bytes_transferred
            exfil_candidates[key]["flows"].append(flow)

            if exfil_candidates[key]["first_time"] is None:
                exfil_candidates[key]["first_time"] = flow.first_seen
            exfil_candidates[key]["last_time"] = flow.last_seen

        # Check each source
        for src_ip, data in exfil_candidates.items():
            for dst_ip, total_bytes in data["destinations"].items():
                # Check threshold
                if total_bytes < config.EXFIL_BYTES_THRESHOLD:
                    continue

                # Check time window
                duration = (data["last_time"] - data["first_time"]).total_seconds()
                if duration > config.EXFIL_WINDOW_SECONDS:
                    continue

                # This is exfiltration!
                bytes_mb = total_bytes / (1024 * 1024)
                logger.info(
                    f"Exfiltration detected: {src_ip} → {dst_ip} "
                    f"({bytes_mb:.1f}MB in {duration:.0f}s)"
                )

                finding = Finding(
                    rule_name=self.rule_name,
                    severity=Severity.CRITICAL,
                    category=RuleCategory.EXFILTRATION,
                    title=f"Data Exfiltration: {src_ip} → {dst_ip}",
                    description=(
                        f"Host {src_ip} transferred {bytes_mb:.1f}MB to "
                        f"{dst_ip} in {duration:.0f} seconds. This large "
                        f"outbound transfer is consistent with data theft."
                    ),
                    evidence={
                        "source_ip": src_ip,
                        "destination_ip": dst_ip,
                        "bytes_transferred": total_bytes,
                        "bytes_mb": round(bytes_mb, 2),
                        "duration_seconds": duration,
                        "throughput_mbps": round(bytes_mb / (duration / 60), 2) if duration > 0 else 0,
                    },
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    timestamp=data["first_time"],
                    mitre_technique="T1020",
                    mitre_tactic="Impact",
                )

                finding.iocs.append(IOC(value=src_ip, ioc_type=IOCType.IP))
                finding.iocs.append(IOC(value=dst_ip, ioc_type=IOCType.IP))

                findings.append(finding)

        return findings
