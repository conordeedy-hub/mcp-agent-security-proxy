import json
import re
from pathlib import Path
from typing import Dict, Any, Tuple


class AgentPolicyEngine:
    """Evaluates AI agent / MCP tool-call payloads against NIST AI RMF-aligned policies."""

    def __init__(self, policy_path: str = "policies.json"):
        self.policy = json.loads(Path(policy_path).read_text(encoding="utf-8"))

    def evaluate_tool_call(self, payload: Dict[str, Any]) -> Tuple[str, int, str]:
        """
        Inspects an incoming agent tool call.
        Returns: (decision, risk_score, reason)
        Decisions: ALLOW | BLOCK | ESCALATE_HUMAN
        """
        agent_id = payload.get("agent_id", "unknown-agent")
        tool_name = payload.get("tool_name", "")
        arguments = payload.get("arguments", {})
        serialized_args = json.dumps(arguments)

        # 1. Tool Allow-List Check (NIST AI RMF: MANAGE / GOVERN)
        if tool_name not in self.policy["allowed_tools"]:
            return (
                "BLOCK",
                95,
                f"Unauthorized tool '{tool_name}' requested by agent '{agent_id}'.",
            )

        # 2. Prompt Injection Detection in Tool Arguments
        lower_args = serialized_args.lower()
        for pattern in self.policy["prompt_injection_patterns"]:
            if pattern in lower_args:
                return (
                    "BLOCK",
                    98,
                    f"Prompt injection signature detected: '{pattern}'.",
                )

        # 3. Destructive SQL Command Prevention
        if tool_name == "query_customer_db":
            sql_query = str(arguments.get("query", "")).upper()
            for keyword in self.policy["blocked_sql_keywords"]:
                if re.search(rf"\b{keyword}\b", sql_query):
                    return (
                        "BLOCK",
                        92,
                        f"Destructive or mutating SQL keyword '{keyword}' blocked.",
                    )

        # 4. Sensitive PII Exfiltration Check
        for pii_type, regex in self.policy["pii_regex_patterns"].items():
            if re.search(regex, serialized_args):
                return (
                    "BLOCK",
                    90,
                    f"Unmasked sensitive PII ({pii_type.upper()}) detected in outbound payload.",
                )

        # 5. Human-in-the-Loop Escalation Gate
        if tool_name in self.policy["require_human_approval_tools"]:
            return (
                "ESCALATE_HUMAN",
                55,
                f"Tool '{tool_name}' requires human approval prior to execution.",
            )

        return ("ALLOW", 10, "Payload passed all policy, SQL, and PII checks.")
