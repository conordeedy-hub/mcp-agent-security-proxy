# MCP & AI Agent Security Proxy (`mcp-agent-security-proxy`)

A lightweight, zero-dependency Python middleware gateway that intercepts AI agent / Model Context Protocol (MCP) tool calls, enforces **NIST AI RMF-aligned security policies**, blocks prompt injections and destructive SQL actions, prevents PII leakage, and writes an immutable **SQLite audit log**.

## Why I Built This
As enterprises deploy autonomous AI agents connected to internal databases and REST APIs, agents become vulnerable to indirect prompt injections, unauthorized tool execution, and accidental PII exfiltration. This project demonstrates a policy-driven security proxy that sits between an AI agent and backend services to inspect, govern, and audit every tool call before execution.

## Key Features
- **Tool Allow-Listing (`policies.json`):** Blocks unapproved or high-privilege tool invocations before they reach backend APIs.
- **Prompt Injection & SQL Guardrails (`guardrails.py`):** Detects injection signatures (`ignore previous instructions`, `system override`) and blocks mutating/destructive SQL commands (`DROP`, `DELETE`, `TRUNCATE`, `UPDATE`).
- **PII Exfiltration Prevention:** Scans outbound payloads for unmasked SSNs and payment card patterns.
- **Human-in-the-Loop Escalation:** Flags sensitive external actions (such as sending client emails) with HTTP `202 ESCALATE_HUMAN` for manual approval.
- **Immutable SQLite Audit Trail (`proxy_server.py`):** Records timestamps, agent IDs, risk scores, latency, and policy decisions in `agent_audit.db` with a `GET /audit-summary` inspection endpoint.

## Quickstart (Zero External Dependencies)
Requires Python 3.10+. No third-party packages or API keys needed.

```bash
git clone https://github.com
cd mcp-agent-security-proxy
python demo.py
```

## Sample Output
```text
1. Safe Read-Only Analytics Query
  -> HTTP 200 | Decision: ALLOW (Risk: 10/100)
  -> Reason:   Payload passed all policy, SQL, and PII checks.

2. Prompt Injection + SQL DROP Attack
  -> HTTP 403 | Decision: BLOCK (Risk: 98/100)
  -> Reason:   Prompt injection signature detected: 'ignore previous instructions'.

3. Unauthorized Shell Execution Attempt
  -> HTTP 403 | Decision: BLOCK (Risk: 95/100)
  -> Reason:   Unauthorized tool 'execute_bash_shell' requested by agent 'rogue-plugin-agent'.
```
