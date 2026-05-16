import pytest
from datetime import datetime
from unittest.mock import patch

from core.models import Finding, Severity, RuleCategory
from ai.prompt_templates import get_template, build_prompt
from ai.explainer import LLMExplainer, Guardrails


class TestPromptTemplates:

    def test_get_template_port_scan(self):
        template = get_template("PORT_SCAN_DETECTED")
        assert template is not None
        assert "{src_ip}" in template
        assert "{dst_ip}" in template
        assert "{ports_scanned}" in template

    def test_get_template_invalid(self):
        template = get_template("INVALID_RULE")
        assert template == ""

    def test_build_prompt(self):
        finding = Finding(
            rule_name="PORT_SCAN_DETECTED",
            severity=Severity.HIGH,
            category=RuleCategory.RECONNAISSANCE,
            title="Test",
            description="Test",
            evidence={
                "src_ip": "192.168.1.100",
                "dst_ip": "10.0.0.1",
                "ports_scanned": "22, 80, 443",
                "duration": "45",
                "port_count": "20",
            },
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            timestamp=None,
            mitre_technique="T1046",
            mitre_tactic="Discovery",
        )

        prompt = build_prompt(finding)
        assert prompt is not None
        assert "192.168.1.100" in prompt
        assert "10.0.0.1" in prompt


class TestGuardrails:

    def test_valid_explanation(self):
        good_explanation = """What happened:
A computer scanned many ports.

Why it matters:
This is reconnaissance.

What to do now:
1. Isolate the computer
2. Check for malware
3. Review logs
4. Update firewall"""

        assert Guardrails.validate_explanation(good_explanation) == True

    def test_missing_sections(self):
        bad_explanation = "A computer scanned ports."
        assert Guardrails.validate_explanation(bad_explanation) == False

    def test_uncertain_language(self):
        bad_explanation = """What happened:
A computer scanned ports on the network.

Why it matters:
I'm not sure if this is real but i assume it could be bad.

What to do now:
1. Isolate the host
2. Review firewall rules
3. Check logs for more activity"""

        assert Guardrails.validate_explanation(bad_explanation) == False

    def test_too_short(self):
        assert Guardrails.validate_explanation("Short") == False

    def test_too_long(self):
        long_text = "x" * 3000
        assert Guardrails.validate_explanation(long_text) == False


class TestLLMExplainer:

    def test_explainer_init(self):
        explainer = LLMExplainer()
        assert explainer.model == "llama-3.1-8b-instant"

    def test_explain_no_api_key(self):
        with patch.dict("os.environ", {}, clear=True):
            explainer = LLMExplainer(api_key=None)

        finding = Finding(
            rule_name="PORT_SCAN_DETECTED",
            severity=Severity.HIGH,
            category=RuleCategory.RECONNAISSANCE,
            title="Test",
            description="Test",
            evidence={"src_ip": "1.1.1.1", "dst_ip": "2.2.2.2",
                     "ports_scanned": "22", "duration": "10", "port_count": "1"},
            src_ip="1.1.1.1",
            dst_ip="2.2.2.2",
            timestamp=datetime.now(),
            mitre_technique="T1046",
            mitre_tactic="Discovery",
        )

        result = explainer.explain(finding)
        assert result is None  # No API key = None
