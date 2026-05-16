import os
from typing import Optional

import config
from core.logger import get_logger
from core.models import Finding
from ai.prompt_templates import build_prompt

logger = get_logger(__name__)


class LLMExplainer:
    """
    Generates plain-English explanations using Groq API.
    Fully grounded in evidence (no hallucinations).
    """

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("GROQ_API_KEY")
        self.model = config.LLM_MODEL
        self.base_url = config.LLM_BASE_URL
        
        if not self.api_key:
            logger.warning("GROQ_API_KEY not set — LLM explanations disabled")
        
        logger.debug("LLMExplainer initialized")

    def explain(self, finding: Finding) -> Optional[str]:
        """
        Generates plain-English explanation for a finding.
        
        Args:
            finding: Finding object
        
        Returns:
            Plain English explanation or None if failed
        """
        if not self.api_key:
            logger.debug(f"LLM disabled — skipping {finding.rule_name}")
            return None

        # Build prompt from evidence
        prompt = build_prompt(finding)
        if not prompt:
            logger.warning(f"No template for {finding.rule_name}")
            return None

        try:
            import requests
            
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            }

            payload = {
                "model": self.model,
                "messages": [
                    {
                        "role": "system",
                        "content": "You are a cybersecurity expert. Always base your response ONLY on the provided evidence. Never speculate or assume. Be concise and clear."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                "temperature": config.LLM_TEMPERATURE,
                "max_tokens": config.LLM_MAX_TOKENS,
            }

            response = requests.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json=payload,
                timeout=30
            )

            if response.status_code == 200:
                result = response.json()
                explanation = result["choices"][0]["message"]["content"]
                
                logger.info(f"LLM explanation generated for {finding.rule_name}")
                return explanation
            
            else:
                logger.warning(f"Groq API error {response.status_code}: {response.text}")
                return None

        except Exception as e:
            logger.error(f"LLM explanation failed: {e}")
            return None


class Guardrails:
    """
    Validates LLM output to prevent hallucinations.
    """

    @staticmethod
    def validate_explanation(explanation: str) -> bool:
        """
        Checks if explanation is safe and grounded.
        
        Args:
            explanation: LLM output
        
        Returns:
            True if valid
        """
        if not explanation:
            return False

        # Must have required sections
        has_what = "What happened:" in explanation or "what happened" in explanation.lower()
        has_why = "Why it matters:" in explanation or "why it matters" in explanation.lower()
        has_todo = "What to do" in explanation or "action" in explanation.lower()

        if not (has_what and has_why and has_todo):
            logger.warning("Explanation missing required sections")
            return False

        # Must be reasonable length (not truncated, not too short)
        if len(explanation) < 100:
            logger.warning("Explanation too short")
            return False

        if len(explanation) > 2000:
            logger.warning("Explanation too long")
            return False

        # Must not contain phrases that indicate fabrication, not just hedging
        dangerous_phrases = [
            "i dont know",
            "i am not sure",
            "i'm not sure",
            "according to my training",
            "i assume",
        ]

        explanation_lower = explanation.lower()
        for phrase in dangerous_phrases:
            if phrase in explanation_lower:
                logger.warning(f"Explanation contains uncertain language: {phrase}")
                return False

        return True
