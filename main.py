import sys
import json
from pathlib import Path
from datetime import datetime

from core.logger import get_logger
from core.validator import validate_pcap_file, ValidationError
from core.parser import parse_pcap, PcapParseError
from core.models import AnalysisReport
from detection.engine import DetectionEngine

logger = get_logger(__name__)


def run_analysis(pcap_path: str) -> None:
    """
    Runs complete ForensiQ analysis on a PCAP file.
    
    Args:
        pcap_path: Path to PCAP file
    """
    pcap_file = Path(pcap_path)
    
    print()
    print("=" * 60)
    print("  ForensiQ — Evidence-Driven Network Forensics")
    print("=" * 60)
    print(f"  File: {pcap_file.name}")
    print(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    print()

    # Step 1: Validate file
    print("[1/3] Validating file...")
    try:
        safe_name, file_hash = validate_pcap_file(pcap_file)
        print(f"      Name   : {safe_name}")
        print(f"      SHA256 : {file_hash}")
        print(f"      Status : VALID")
    except ValidationError as e:
        print(f"      REJECTED: {e}")
        sys.exit(1)

    print()

    # Step 2: Parse PCAP
    print("[2/3] Parsing PCAP...")
    try:
        analysis_start = datetime.now()
        flows, stats = parse_pcap(pcap_file)
        print(f"      Packets : {stats['packet_count']:,}")
        print(f"      Flows   : {stats['flow_count']:,}")
        print(f"      Bytes   : {stats['bytes_total']:,}")
    except PcapParseError as e:
        print(f"      FAILED: {e}")
        sys.exit(1)

    print()

    # Step 3: Run detection rules
    print("[3/3] Running detection rules...")
    engine = DetectionEngine()
    findings = engine.run(flows)
    analysis_end = datetime.now()

    print()

    # Build report
    report = AnalysisReport(
        pcap_filename=safe_name,
        pcap_hash=file_hash,
        analysis_start=analysis_start,
        analysis_end=analysis_end,
        total_flows=stats["flow_count"],
        total_packets=stats["packet_count"],
        total_bytes=stats["bytes_total"],
        findings=findings,
    )

    # Print results
    print("=" * 60)
    print("  ANALYSIS RESULTS")
    print("=" * 60)
    print(f"  Duration : {report.duration_seconds:.1f} seconds")
    print(f"  Flows    : {report.total_flows:,}")
    print(f"  Findings : {len(findings)}")
    print()

    severity_counts = report.finding_count_by_severity
    print(f"  CRITICAL : {severity_counts['CRITICAL']}")
    print(f"  HIGH     : {severity_counts['HIGH']}")
    print(f"  MEDIUM   : {severity_counts['MEDIUM']}")
    print(f"  LOW      : {severity_counts['LOW']}")
    print()

    if not findings:
        print("  No threats detected.")
    else:
        print("=" * 60)
        print("  DETAILED FINDINGS")
        print("=" * 60)

        for i, finding in enumerate(findings, 1):
            print()
            print(f"  [{i}] {finding.severity.value} — {finding.title}")
            print(f"      Rule     : {finding.rule_name}")
            print(f"      MITRE    : {finding.mitre_technique} ({finding.mitre_tactic})")
            print(f"      Source   : {finding.src_ip}")
            print(f"      Target   : {finding.dst_ip}")
            print(f"      Time     : {finding.timestamp}")
            print()
            print(f"      DESCRIPTION:")
            print(f"      {finding.description}")
            print()
            print(f"      EVIDENCE:")
            for key, value in finding.evidence.items():
                print(f"        {key}: {value}")
            print()
            print("  " + "-" * 56)

    # Save JSON report
    output_file = Path(f"outputs/{pcap_file.stem}_report.json")
    output_file.parent.mkdir(exist_ok=True)
    with open(output_file, "w") as f:
        f.write(report.to_json())

    print()
    print(f"  Report saved: {output_file}")
    print("=" * 60)
    print()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 main.py <path_to_pcap>")
        print("Example: python3 main.py sample.pcap")
        sys.exit(1)

    run_analysis(sys.argv[1])
