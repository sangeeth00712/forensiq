# detection/rules/beaconing.py
# ─────────────────────────────────────────────────────────────
# ForensiQ — C2 Beaconing Detection Rule
#
# Detects malware calling home at regular intervals (heartbeat pattern).
#
# Author  : Sangeeth
# Version : 1.0.0
# ─────────────────────────────────────────────────────────────

from collections import defaultdict
from statistics import mean, stdev
from typing import List, Optional

import config
from core.logger import get_logger
from core.models import Finding, Flow, Severity, RuleCategory, IOC, IOCType
from detection.rules.base_rule import BaseRule

logger = get_logger(__name__)


class BeaconingRule(BaseRule):
    """
    Detects C2 beaconing (malware calling home).
    
    Pattern:
    - Same source → same destination IP
    - At regular intervals (e.g. every 60 seconds)
    - 5+ connections
    - Consistent interval (within 10% tolerance)
    
    MITRE ATT&CK: T1071 (Application Layer Protocol)
    """

    @property
    def rule_name(self) -> str:
        return "C2_BEACONING_DETECTED"

    @property
    def description(self) -> str:
        return "Detects command & control beaconing (malware calling home)"

    def _calculate_intervals(self, timestamps: List) -> Optional[dict]:
        """
        Calculates interval statistics between timestamps.
        
        Args:
            timestamps: Sorted list of datetime objects
        
        Returns:
            Dict with mean, stdev, coefficient_of_variation, or None
        """
        if len(timestamps) < 2:
            return None

        intervals = []
        for i in range(1, len(timestamps)):
            delta = (timestamps[i] - timestamps[i-1]).total_seconds()
            intervals.append(delta)

        if not intervals:
            return None

        mean_interval = mean(intervals)
        if len(intervals) > 1:
            std_dev = stdev(intervals)
        else:
            std_dev = 0

        # Coefficient of variation (std dev / mean) — lower = more regular
        if mean_interval > 0:
            cv = std_dev / mean_interval
        else:
            cv = float('inf')

        return {
            "intervals": intervals,
            "mean": mean_interval,
            "stdev": std_dev,
            "cv": cv,  # Coefficient of variation
        }

    def detect(self, flows: List[Flow]) -> List[Finding]:
        """
        Analyzes flows for C2 beaconing pattern.
        
        Algorithm:
        1. Group flows by (src_ip, dst_ip, dst_port) tuple
        2. For each group, calculate intervals between connections
        3. Check if intervals are regular (low coefficient of variation)
        4. If regular AND >= threshold connections, flag as beacon
        
        Args:
            flows: List of flows to analyze
        
        Returns:
            List of Finding objects
        """
        findings = []

        # Group flows by source, destination, port
        beacon_candidates = defaultdict(list)

        for flow in flows:
            # Only TCP flows (command & control usually over TCP)
            if flow.protocol.value != "TCP":
                continue

            key = (flow.src_ip, flow.dst_ip, flow.dst_port)
            beacon_candidates[key].append(flow)

        # Analyze each candidate
        for (src_ip, dst_ip, dst_port), flows_group in beacon_candidates.items():
            # Must have minimum connections
            if len(flows_group) < config.BEACON_MIN_CONNECTIONS:
                continue

            # Sort by timestamp
            flows_group.sort(key=lambda f: f.first_seen)
            timestamps = [f.first_seen for f in flows_group]

            # Calculate interval statistics
            stats = self._calculate_intervals(timestamps)
            if not stats:
                continue

            mean_interval = stats["mean"]
            cv = stats["cv"]  # Coefficient of variation

            # Check if interval is within acceptable range
            if mean_interval < config.BEACON_MIN_INTERVAL_SEC:
                continue
            if mean_interval > config.BEACON_MAX_INTERVAL_SEC:
                continue

            # Check if intervals are regular (low variance)
            # cv < 0.10 means intervals are very regular
            tolerance = config.BEACON_INTERVAL_TOLERANCE
            if cv > tolerance:
                continue

            # This is a beacon!
            logger.info(
                f"Beaconing detected: {src_ip} → {dst_ip}:{dst_port} "
                f"every {mean_interval:.0f} seconds (CV: {cv:.2f})"
            )

            finding = Finding(
                rule_name=self.rule_name,
                severity=Severity.CRITICAL,
                category=RuleCategory.COMMAND_CONTROL,
                title=f"C2 Beaconing: {src_ip} → {dst_ip}:{dst_port}",
                description=(
                    f"Host {src_ip} established regular connections to "
                    f"{dst_ip}:{dst_port} with intervals of ~{mean_interval:.0f}s. "
                    f"This heartbeat pattern is consistent with command & control "
                    f"malware communicating with its C2 server."
                ),
                evidence={
                    "source_ip": src_ip,
                    "destination_ip": dst_ip,
                    "destination_port": dst_port,
                    "connection_count": len(flows_group),
                    "mean_interval_seconds": mean_interval,
                    "interval_variance": cv,
                    "intervals_seconds": [round(i, 2) for i in stats["intervals"]],
                },
                src_ip=src_ip,
                dst_ip=dst_ip,
                timestamp=timestamps[0],
                mitre_technique="T1071",
                mitre_tactic="Command and Control",
            )

            # Add both IPs as IOCs
            finding.iocs.append(IOC(value=src_ip, ioc_type=IOCType.IP))
            finding.iocs.append(IOC(value=dst_ip, ioc_type=IOCType.IP))

            findings.append(finding)

        return findings
