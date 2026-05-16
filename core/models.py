# core/models.py
# ─────────────────────────────────────────────────────────────
# ForensiQ — Core Data Models
#
# These are the fundamental data structures that flow through
# the entire system: parser → detection → enrichment → output
#
# Author  : Sangeeth
# Version : 1.0.0
# Standard: Production-grade, type-safe, fully validated
# ─────────────────────────────────────────────────────────────

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from core.logger import get_logger

logger = get_logger(__name__)


# ─────────────────────────────────────────────
# ENUMS — Controlled vocabulary, no magic strings
# ─────────────────────────────────────────────

class Severity(str, Enum):
    """
    Threat severity levels.
    Using str + Enum so values serialize cleanly to JSON.

    LOW:      Informational, not an immediate threat
    MEDIUM:   Worth investigation, could be false positive
    HIGH:     Likely real threat, requires immediate action
    CRITICAL: Active attack in progress, respond now
    """
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


class Protocol(str, Enum):
    """
    Network layer protocols we can detect.
    Restricted set — only protocols parser actually extracts.
    """
    TCP   = "TCP"
    UDP   = "UDP"
    ICMP  = "ICMP"
    DNS   = "DNS"
    HTTP  = "HTTP"
    HTTPS = "HTTPS"
    TLS   = "TLS"
    OTHER = "OTHER"


class IOCType(str, Enum):
    """
    Types of Indicators of Compromise.
    Each type is enriched differently.
    """
    IP     = "ip"
    DOMAIN = "domain"
    HASH   = "hash"
    EMAIL  = "email"
    URL    = "url"


class RuleCategory(str, Enum):
    """
    Categories of detection rules.
    Used for grouping findings in reports.
    """
    RECONNAISSANCE = "reconnaissance"
    COMMAND_CONTROL = "command_control"
    EXFILTRATION = "exfiltration"
    LATERAL_MOVEMENT = "lateral_movement"
    IMPACT = "impact"
    PERSISTENCE = "persistence"


# ─────────────────────────────────────────────
# FLOW — One network conversation
# ─────────────────────────────────────────────

@dataclass
class Flow:
    """
    Represents a single reconstructed network conversation
    between two endpoints.

    A Flow is the fundamental unit of analysis in ForensiQ.
    All detection rules operate on lists of Flow objects.

    The parser creates flows from raw packets.
    Detection rules examine flows to find threats.
    """

    # Required fields
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: Protocol
    first_seen: datetime
    last_seen: datetime

    # Statistics
    packet_count: int = 0
    bytes_transferred: int = 0
    bytes_reversed: int = 0  # bytes from dst to src

    # Protocol-specific details
    dns_query: Optional[str] = None
    http_host: Optional[str] = None
    http_method: Optional[str] = None
    tls_sni: Optional[str] = None
    tls_ja3: Optional[str] = None

    @property
    def duration_seconds(self) -> float:
        """
        How long this conversation lasted.
        Returns 0.0 if timestamps are identical (single packet).
        """
        delta = (self.last_seen - self.first_seen).total_seconds()
        return max(delta, 0.0)

    @property
    def bytes_per_second(self) -> float:
        """
        Average throughput of this flow.
        Useful for detecting data exfiltration.
        """
        duration = self.duration_seconds
        if duration == 0:
            return 0.0
        return self.bytes_transferred / duration

    @property
    def flow_id(self) -> str:
        """
        Unique identifier for this flow.
        Format: src_ip:src_port-dst_ip:dst_port-protocol
        """
        return (
            f"{self.src_ip}:{self.src_port}"
            f"-{self.dst_ip}:{self.dst_port}"
            f"-{self.protocol.value}"
        )

    def to_dict(self) -> Dict[str, Any]:
        """
        Converts flow to JSON-safe dictionary.
        Datetime objects converted to ISO format strings.
        """
        return {
            "flow_id": self.flow_id,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol.value,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "duration_seconds": self.duration_seconds,
            "packet_count": self.packet_count,
            "bytes_transferred": self.bytes_transferred,
            "bytes_per_second": self.bytes_per_second,
            "dns_query": self.dns_query,
            "http_host": self.http_host,
            "http_method": self.http_method,
            "tls_sni": self.tls_sni,
        }

    def __str__(self) -> str:
        """Human-readable representation."""
        return (
            f"{self.src_ip}:{self.src_port} → "
            f"{self.dst_ip}:{self.dst_port} "
            f"({self.protocol.value}) "
            f"{self.packet_count} pkts "
            f"{self.bytes_transferred} bytes"
        )


# ─────────────────────────────────────────────
# IOC — Indicator of Compromise
# ─────────────────────────────────────────────

@dataclass
class IOC:
    """
    Represents a single Indicator of Compromise.

    IOCs are extracted from findings and later enriched
    with threat intelligence data (VirusTotal, OTX, etc.).

    Example:
        Finding detects connection to "evil.com"
        → IOC created for "evil.com"
        → Enrichment module looks it up on VirusTotal
        → IOC updated with VT score, malware family, etc.
    """

    # Core fields
    value: str                                  # IP, domain, hash, etc
    ioc_type: IOCType

    # Enrichment data
    malicious: bool = False
    vt_score: Optional[str] = None               # "45/72"
    vt_link: Optional[str] = None
    known_malware: Optional[str] = None          # e.g. "Emotet"
    country: Optional[str] = None                # GeoIP
    asn: Optional[str] = None
    enriched: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Converts IOC to JSON-safe dictionary."""
        return {
            "value": self.value,
            "ioc_type": self.ioc_type.value,
            "malicious": self.malicious,
            "vt_score": self.vt_score,
            "vt_link": self.vt_link,
            "known_malware": self.known_malware,
            "country": self.country,
            "asn": self.asn,
            "enriched": self.enriched,
        }

    def __str__(self) -> str:
        """Human-readable representation."""
        status = "MALICIOUS" if self.malicious else "unknown"
        return f"{self.value} ({self.ioc_type.value}) - {status}"


# ─────────────────────────────────────────────
# FINDING — One detected threat
# ─────────────────────────────────────────────

@dataclass
class Finding:
    """
    Represents a single detected threat event.

    CRITICAL DESIGN RULE:
    Every Finding MUST include evidence — the raw data
    that triggered the alert. A finding without evidence
    is not suitable for forensic investigations.

    Example:
        Rule: "PORT_SCAN_DETECTED"
        Evidence: {"scanned_ports": [22, 80, 443, 3306],
                   "duration": 45, "target_host": "10.0.0.1"}
        Description: "Host 192.168.1.10 scanned 4 ports on 10.0.0.1..."

    This evidence allows someone to:
    - Verify the finding is correct
    - Use it in a legal case (court-admissible)
    - Investigate further if needed
    """

    # Core identification
    rule_name: str                              # "PORT_SCAN_DETECTED"
    severity: Severity
    category: RuleCategory
    title: str                                  # Short summary
    description: str                            # Full explanation

    # Evidence — this is mandatory
    evidence: Dict[str, Any]

    # Network information
    src_ip: str
    dst_ip: str
    timestamp: datetime

    # MITRE ATT&CK mapping
    mitre_technique: str                        # "T1046"
    mitre_tactic: str                           # "Discovery"

    # ML confidence added later (default: no ML score yet)
    confidence: float = 0.0                     # 0.0 to 1.0

    # IOCs extracted from this finding
    iocs: List[IOC] = field(default_factory=list)
    explanation: Optional[str] = None  # Plain English summary

    def __post_init__(self) -> None:
        """
        Validates finding integrity after creation.

        ENFORCES: No finding without evidence
        This is not optional — it's a data integrity constraint.
        """
        if not self.evidence:
            error_msg = (
                f"Finding '{self.rule_name}' created with empty evidence. "
                f"Every finding must include verifiable evidence. "
                f"This is a forensics-grade requirement and cannot be bypassed."
            )
            logger.error(error_msg)
            raise ValueError(error_msg)

        if not (0.0 <= self.confidence <= 1.0):
            error_msg = (
                f"Confidence score must be 0.0-1.0, got {self.confidence}"
            )
            logger.error(error_msg)
            raise ValueError(error_msg)

        logger.debug(
            f"Finding created: {self.rule_name} | "
            f"Severity: {self.severity.value} | "
            f"Evidence keys: {list(self.evidence.keys())}"
        )

    def to_dict(self) -> Dict[str, Any]:
        """
        Converts finding to JSON-safe dictionary.
        Used for JSON exports, PDF reports, STIX format.
        """
        return {
            "rule_name": self.rule_name,
            "severity": self.severity.value,
            "category": self.category.value,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "timestamp": self.timestamp.isoformat(),
            "mitre_technique": self.mitre_technique,
            "mitre_tactic": self.mitre_tactic,
            "confidence": round(self.confidence, 2),
            "iocs": [ioc.to_dict() for ioc in self.iocs],
            "explanation": self.explanation,
        }

    def to_json(self) -> str:
        """Serializes finding to JSON string."""
        return json.dumps(self.to_dict(), indent=2)

    def __str__(self) -> str:
        """Human-readable representation."""
        return (
            f"[{self.severity.value}] {self.rule_name} | "
            f"{self.src_ip} → {self.dst_ip} | "
            f"{self.title}"
        )


# ─────────────────────────────────────────────
# ANALYSIS REPORT — Collection of findings
# ─────────────────────────────────────────────

@dataclass
class AnalysisReport:
    """
    Complete analysis report for one PCAP file.
    Generated after parser + all detection rules run.
    This is what gets exported to PDF/JSON/STIX.
    """

    # File metadata
    pcap_filename: str
    pcap_hash: str                              # SHA-256
    analysis_start: datetime
    analysis_end: datetime

    # Results
    total_flows: int = 0
    findings: List[Finding] = field(default_factory=list)

    # Statistics
    total_packets: int = 0
    total_bytes: int = 0
    unique_src_ips: int = 0
    unique_dst_ips: int = 0

    @property
    def duration_seconds(self) -> float:
        """How long the analysis took."""
        delta = (self.analysis_end - self.analysis_start).total_seconds()
        return max(delta, 0.0)

    @property
    def finding_count_by_severity(self) -> Dict[str, int]:
        """Count of findings grouped by severity."""
        counts = {s.value: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    @property
    def has_critical_findings(self) -> bool:
        """Returns True if any CRITICAL findings exist."""
        return any(f.severity == Severity.CRITICAL for f in self.findings)

    def to_dict(self) -> Dict[str, Any]:
        """Converts entire report to dictionary."""
        return {
            "pcap_filename": self.pcap_filename,
            "pcap_hash": self.pcap_hash,
            "analysis_start": self.analysis_start.isoformat(),
            "analysis_end": self.analysis_end.isoformat(),
            "analysis_duration_seconds": self.duration_seconds,
            "total_flows": self.total_flows,
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "unique_src_ips": self.unique_src_ips,
            "unique_dst_ips": self.unique_dst_ips,
            "finding_count": len(self.findings),
            "findings_by_severity": self.finding_count_by_severity,
            "has_critical": self.has_critical_findings,
            "findings": [f.to_dict() for f in self.findings],
        }

    def to_json(self) -> str:
        """Serializes entire report to JSON."""
        return json.dumps(self.to_dict(), indent=2, default=str)

    def summary(self) -> str:
        """One-line summary for console output."""
        counts = self.finding_count_by_severity
        return (
            f"Analysis complete | "
            f"Flows: {self.total_flows} | "
            f"Findings: {len(self.findings)} | "
            f"Critical: {counts['CRITICAL']} | "
            f"High: {counts['HIGH']} | "
            f"Duration: {self.duration_seconds:.1f}s"
        )
