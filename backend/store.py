"""Almacén de resultados (SQLite): es el contrato con el dashboard.

El dashboard SOLO lee de aquí. Tablas:
  prefilter     una fila por alerta: decisión del prefiltro + traza de comprobaciones
  tickets       una fila por ticket (formato ticket_salida.schema.json) + traza del agente
  ticket_alerts relación ticket ↔ alertas agrupadas
  human_actions decisiones del analista (aprobar, corregir, escalar) desde el dashboard
"""
import json, os, sqlite3

DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "triage.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS prefilter (
  alert_id TEXT PRIMARY KEY, created_at TEXT, rule_id TEXT, rule_name TEXT, source_product TEXT,
  rule_severity TEXT, disposition TEXT, verdict TEXT, severity TEXT, severity_rationale TEXT,
  confidence REAL, title TEXT, basis TEXT, group_key TEXT, route_reason TEXT,
  injection TEXT, recommended_actions TEXT, open_questions TEXT, trace TEXT);
CREATE TABLE IF NOT EXISTS tickets (
  ticket_id TEXT PRIMARY KEY, created_at TEXT, origin TEXT, status TEXT,
  verdict TEXT, severity TEXT, confidence REAL, title TEXT, escalate INTEGER,
  ticket_json TEXT, trace TEXT, model TEXT, tokens_in INTEGER, tokens_out INTEGER, triage_seconds REAL);
CREATE TABLE IF NOT EXISTS ticket_alerts (ticket_id TEXT, alert_id TEXT, PRIMARY KEY (ticket_id, alert_id));
CREATE TABLE IF NOT EXISTS human_actions (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, ticket_id TEXT, analyst TEXT,
  action TEXT, detail TEXT);
"""


def connect(path=DB):
    con = sqlite3.connect(path)
    con.executescript(SCHEMA)
    return con


def save_prefilter(con, alert, d):
    con.execute("INSERT OR REPLACE INTO prefilter VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (
        d.alert_id, alert["created_at"], d.rule_id, alert["rule_name"], alert["source_product"],
        alert["severity"], d.disposition, d.verdict, d.severity, d.severity_rationale, d.confidence,
        d.title, d.basis, d.group_key, d.route_reason, json.dumps(d.injection, ensure_ascii=False),
        json.dumps(d.recommended_actions, ensure_ascii=False), json.dumps(d.open_questions, ensure_ascii=False),
        json.dumps(d.trace, ensure_ascii=False, default=str)))


def save_ticket(con, ticket: dict, origin: str, trace: list, created_at: str, model="", tin=0, tout=0):
    con.execute("INSERT OR REPLACE INTO tickets VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (
        ticket["ticket_id"], created_at, origin, "pending_review" if ticket["escalation"]["escalate"] else "closed",
        ticket["verdict"], ticket["severity"], ticket["confidence"], ticket["title"],
        int(ticket["escalation"]["escalate"]), json.dumps(ticket, ensure_ascii=False),
        json.dumps(trace, ensure_ascii=False, default=str), model, tin, tout, ticket.get("triage_seconds", 0)))
    for aid in ticket["alert_ids"]:
        con.execute("INSERT OR REPLACE INTO ticket_alerts VALUES (?,?)", (ticket["ticket_id"], aid))
