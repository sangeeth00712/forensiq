import re
from typing import Optional
from core.models import Finding
from core.logger import get_logger

logger = get_logger(__name__)


PROMPT_TEMPLATES = {
    "PORT_SCAN_DETECTED": r"""You are a cybersecurity expert explaining a network threat to a non-technical audience.

FINDING: Port scan detected
EVIDENCE:
- Source IP: {src_ip}
- Target IP: {dst_ip}
- Ports scanned: {ports_scanned}
- Duration: {duration} seconds
- Port count: {port_count}

YOUR TASK:
1. Explain in 2-3 sentences what happened (what is port scanning?)
2. Explain in 1-2 sentences why this is bad
3. Provide 3-4 specific actions to take now

Use ONLY the evidence above. Do not speculate. Be concise and clear for a non-technical person.

RESPONSE FORMAT:
What happened:
[explanation]

Why it matters:
[importance]

What to do now:
1. [action]
2. [action]
3. [action]
4. [action]""",

    "BRUTE_FORCE_DETECTED": r"""You are a cybersecurity expert explaining a network threat to a non-technical audience.

FINDING: Brute force attack detected
EVIDENCE:
- Source IP: {src_ip}
- Target IP: {dst_ip}
- Target service: {service}
- Target port: {port}
- Attempt count: {attempt_count}
- Duration: {duration} seconds
- Attempts per second: {attempts_per_second}

YOUR TASK:
1. Explain what brute force is (2-3 sentences)
2. Explain why repeated failed attempts = attack (1-2 sentences)
3. Provide 3-4 actions to take now

Use ONLY the evidence above. Do not speculate. Be concise.

RESPONSE FORMAT:
What happened:
[explanation]

Why it matters:
[importance]

What to do now:
1. [action]
2. [action]
3. [action]
4. [action]""",

    "C2_BEACONING_DETECTED": r"""You are a cybersecurity expert explaining a network threat to a non-technical audience.

FINDING: Command & Control beaconing detected
EVIDENCE:
- Source IP: {src_ip}
- Destination IP: {dst_ip}
- Destination port: {dst_port}

YOUR TASK:
1. Explain what beaconing is (2-3 sentences)
2. Explain why regular connections = malware (1-2 sentences)
3. Provide 3-4 actions to take now

Use ONLY the evidence above. Do not speculate. Be concise.

RESPONSE FORMAT:
What happened:
[explanation]

Why it matters:
[importance]

What to do now:
1. [action]
2. [action]
3. [action]
4. [action]""",

    "DATA_EXFILTRATION_DETECTED": r"""You are a cybersecurity expert explaining a network threat to a non-technical audience.

FINDING: Data exfiltration detected
EVIDENCE:
- Source IP: {src_ip}
- Destination IP: {dst_ip}
- Data transferred: {bytes_mb} MB
- Duration: {duration} seconds

YOUR TASK:
1. Explain what data theft is (2-3 sentences)
2. Explain why this much data transfer = bad (1-2 sentences)
3. Provide 3-4 actions to take now

Use ONLY the evidence above. Do not speculate. Be concise.

RESPONSE FORMAT:
What happened:
[explanation]

Why it matters:
[importance]

What to do now:
1. [action]
2. [action]
3. [action]
4. [action]""",

    "DNS_TUNNELING_DETECTED": r"""You are a cybersecurity expert explaining a network threat to a non-technical audience.

FINDING: DNS tunneling detected
EVIDENCE:
- Source IP: {src_ip}
- Suspicious queries: {suspicious_query_count}

YOUR TASK:
1. Explain what DNS tunneling is (2-3 sentences)
2. Explain why unusual DNS = bad (1-2 sentences)
3. Provide 3-4 actions to take now

Use ONLY the evidence above. Do not speculate. Be concise.

RESPONSE FORMAT:
What happened:
[explanation]

Why it matters:
[importance]

What to do now:
1. [action]
2. [action]
3. [action]
4. [action]""",
}


def get_template(rule_name: str) -> str:
    """Gets prompt template for a rule."""
    result = PROMPT_TEMPLATES.get(rule_name, "")
    logger.debug(f"get_template({rule_name}) -> {'found' if result else 'not found'}")
    return result


def build_prompt(finding: Finding) -> Optional[str]:
    """
    Builds a complete prompt from finding evidence.
    
    Args:
        finding: Finding object with evidence
    
    Returns:
        Complete prompt ready for LLM, or None if template not found
    """
    template = get_template(finding.rule_name)
    
    if not template:
        logger.warning(f"No template for {finding.rule_name}")
        return None
    
    try:
        # Extract placeholder keys from template
        placeholders = re.findall(r"\{(\w+)\}", template)
        logger.debug(f"Template placeholders: {placeholders}")
        
        # Merge evidence with top-level finding fields so templates can use {src_ip}/{dst_ip}
        evidence_dict = dict(finding.evidence) if finding.evidence else {}
        evidence_dict.setdefault("src_ip", finding.src_ip)
        evidence_dict.setdefault("dst_ip", finding.dst_ip)
        logger.debug(f"Evidence keys: {evidence_dict.keys()}")
        
        # Format template with available evidence
        prompt = template.format_map({
            key: evidence_dict.get(key, "")
            for key in placeholders
        })
        
        logger.debug(f"Prompt built successfully for {finding.rule_name}")
        return prompt
    
    except Exception as e:
        logger.error(f"build_prompt failed: {e}")
        return None
