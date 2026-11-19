import json
import sqlite3
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from guardrails import AgentPolicyEngine

DB_PATH = "agent_audit.db"


def init_db(db_path: str = DB_PATH) -> None:
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp_utc TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                decision TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                reason TEXT NOT NULL,
                latency_ms REAL NOT NULL,
                raw_payload TEXT NOT NULL
            )
            """
        )
        conn.commit()


def log_decision(
    agent_id: str,
    tool_name: str,
    decision: str,
    risk_score: int,
    reason: str,
    latency_ms: float,
    payload: dict,
    db_path: str = DB_PATH,
) -> None:
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO audit_logs
            (timestamp_utc, agent_id, tool_name, decision, risk_score, reason, latency_ms, raw_payload)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now(timezone.utc).isoformat(),
                agent_id,
                tool_name,
                decision,
                risk_score,
                reason,
                round(latency_ms, 2),
                json.dumps(payload),
            ),
        )
        conn.commit()


class AgentFirewallHandler(BaseHTTPRequestHandler):
    engine = AgentPolicyEngine()

    def _send_json(self, status_code: int, body: dict) -> None:
        encoded = json.dumps(body, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:
        if self.path == "/audit-summary":
            with sqlite3.connect(DB_PATH) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "SELECT id, timestamp_utc, agent_id, tool_name, decision, risk_score, reason, latency_ms "
                    "FROM audit_logs ORDER BY id DESC LIMIT 20"
                ).fetchall()
            self._send_json(200, {"recent_events": [dict(r) for r in rows]})
        else:
            self._send_json(404, {"error": "Endpoint not found. Use POST /intercept or GET /audit-summary"})

    def do_POST(self) -> None:
        if self.path != "/intercept":
            self._send_json(404, {"error": "Endpoint not found. Use POST /intercept"})
            return

        start = time.perf_counter()
        content_length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_length).decode("utf-8")

        try:
            payload = json.loads(raw_body)
        except json.JSONDecodeError:
            self._send_json(400, {"error": "Invalid JSON payload"})
            return

        decision, risk_score, reason = self.engine.evaluate_tool_call(payload)
        latency_ms = (time.perf_counter() - start) * 1000

        log_decision(
            agent_id=payload.get("agent_id", "unknown-agent"),
            tool_name=payload.get("tool_name", "unknown-tool"),
            decision=decision,
            risk_score=risk_score,
            reason=reason,
            latency_ms=latency_ms,
            payload=payload,
        )

        status_map = {"ALLOW": 200, "ESCALATE_HUMAN": 202, "BLOCK": 403}
        self._send_json(
            status_map[decision],
            {
                "decision": decision,
                "risk_score": risk_score,
                "reason": reason,
                "latency_ms": round(latency_ms, 2),
            },
        )

    def log_message(self, format: str, *args) -> None:
        return  # Keep console output clean


def run_server(port: int = 8080) -> None:
    init_db()
    server = HTTPServer(("127.0.0.1", port), AgentFirewallHandler)
    print(f"[MCP Agent Security Proxy] Listening on http://127.0.0.1:{port}")
    server.serve_forever()


if __name__ == "__main__":
    run_server()
