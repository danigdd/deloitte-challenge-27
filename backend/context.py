"""Consultas sobre tarvia.duckdb.

Son las mismas funciones que usará el agente LLM como herramientas. Cada llamada queda
registrada en una `Trace`, que es lo que el dashboard enseña como «qué consultó el sistema».
"""
import json, os, time
from datetime import timedelta
import duckdb

DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tarvia.duckdb")
LOG_SOURCES = ["ad_events", "ai_gateway", "cicd_builds", "cloudtrail", "dlp", "dns", "ecom_account",
               "ecom_auth", "edr_events", "email", "email_clicks", "firewall", "idp_audit",
               "idp_signins", "proxy", "sql_audit", "vpn", "waf"]


class Trace:
    """Registro de pasos de un triaje (herramienta, argumentos, resultado resumido)."""
    def __init__(self):
        self.steps = []

    def add(self, tool, args, result_summary, kind="query"):
        self.steps.append({"t": round(time.time(), 3), "kind": kind, "tool": tool,
                           "args": args, "result": result_summary})

    def check(self, name, passed: bool, detail: str):
        """Comprobación de una regla de política (lo que el dashboard pinta como ✓ / ✗)."""
        self.steps.append({"t": round(time.time(), 3), "kind": "check", "tool": name,
                           "args": {}, "result": detail, "passed": passed})


class Ctx:
    def __init__(self, db_path=DB):
        self.con = duckdb.connect(db_path, read_only=True)
        self._assets = {r["hostname"].lower(): r for r in self._rows("SELECT * FROM activos")}
        self._assets_ip = {r["ip"]: r for r in self._assets.values()}
        self._users = {}
        for r in self._rows("SELECT * FROM usuarios"):
            self._users[r["upn"].lower()] = r
            self._users[r["username"].lower()] = r
        self._hr = self._rows("SELECT * FROM eventos_rrhh")
        self._changes = self._rows("SELECT * FROM calendario_cambios")

    # -- utilidades --------------------------------------------------------------------
    def _rows(self, sql, params=None):
        cur = self.con.execute(sql, params or [])
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]

    # -- herramientas ------------------------------------------------------------------
    def get_alert(self, alert_id):
        r = self.con.execute("SELECT raw FROM alerts WHERE alert_id=?", [alert_id]).fetchone()
        return json.loads(r[0]) if r else None

    def get_asset(self, key, trace: Trace = None):
        a = self._assets.get(str(key).lower()) or self._assets_ip.get(str(key))
        if a:
            a = {**a, "vulnerabilities": self._rows("SELECT * FROM vulnerabilidades WHERE hostname=?", [a["hostname"]])}
        if trace:
            trace.add("get_asset", {"key": key},
                      f"{a['hostname']} · criticidad {a['criticality']} · {a['zone']} · {a['business_service']}"
                      if a else "no está en la CMDB (¿externo o no gestionado?)")
        return a

    def get_user(self, key, trace: Trace = None):
        k = str(key).lower().replace("tarvia\\", "")
        u = self._users.get(k)
        if u:
            u = {**u, "hr_events": [h for h in self._hr if h["usuario"].lower() == u["upn"].lower()]}
        if trace:
            if u:
                flags = [f for f, v in (("VIP", u["vip"]), ("privilegiado", u["privileged"])) if v == "True"]
                hr = "; ".join(f"{h['tipo']} ({h['detalle']})" for h in u["hr_events"]) or "sin eventos RRHH"
                trace.add("get_user", {"key": key}, f"{u['title']} · {u['department']} · {u['account_type']}"
                          f"{' · ' + ', '.join(flags) if flags else ''} · {hr}")
            else:
                trace.add("get_user", {"key": key}, "no está en el directorio")
        return u

    def get_events(self, source, event_ids, trace: Trace = None):
        if source not in LOG_SOURCES or not event_ids:
            return []
        rows = self._rows(f"SELECT * EXCLUDE (ts) FROM {source} WHERE event_id IN ({','.join('?' * len(event_ids))})",
                          list(event_ids))
        if trace:
            trace.add("get_events", {"source": source, "ids": list(event_ids)[:10]}, f"{len(rows)} eventos")
        return rows

    def get_related_events(self, alert, trace: Trace = None):
        """Resuelve los related_events de una alerta a sus logs por prefijo de ID."""
        prefix = {"EDR": "edr_events", "EML": "email", "DNS": "dns", "PRX": "proxy", "WAF": "waf",
                  "SIGN": "idp_signins", "AUD": "idp_audit", "AIG": "ai_gateway", "ECA": "ecom_auth",
                  "ECO": "ecom_account", "VPN": "vpn", "DLP": "dlp", "SQL": "sql_audit", "CT": "cloudtrail",
                  "FW": "firewall", "CLK": "email_clicks", "CI": "cicd_builds", "ADE": "ad_events"}
        by_src = {}
        for eid in alert.get("related_events", []):
            src = prefix.get(eid.split("-")[0])
            if src:
                by_src.setdefault(src, []).append(eid)
        out = {s: self.get_events(s, ids) for s, ids in by_src.items()}
        if trace:
            trace.add("get_related_events", {"alert_id": alert["alert_id"]},
                      ", ".join(f"{s}: {len(v)}" for s, v in out.items()) or "sin eventos relacionados")
        return out

    def search_logs(self, source, text, around=None, hours=24, limit=200, trace: Trace = None):
        """Busca `text` en cualquier campo de la fuente, opcionalmente en ±hours alrededor de `around`."""
        if source not in LOG_SOURCES:
            raise ValueError(f"fuente desconocida: {source}")
        sql = f"SELECT * EXCLUDE (ts) FROM {source} t WHERE CAST(to_json(t) AS VARCHAR) ILIKE ?"
        params = [f"%{text}%"]
        if around is not None:
            sql += " AND ts BETWEEN ? AND ?"
            params += [around - timedelta(hours=hours), around + timedelta(hours=hours)]
        sql += f" ORDER BY timestamp LIMIT {int(limit)}"
        rows = self._rows(sql, params)
        if trace:
            win = f" ±{hours}h" if around is not None else ""
            trace.add("search_logs", {"source": source, "q": text, "window": win.strip()},
                      f"{len(rows)} eventos{' (truncado)' if len(rows) >= limit else ''}")
        return rows

    def email_by_message_id(self, message_id, trace: Trace = None):
        rows = self._rows("SELECT * EXCLUDE (ts) FROM email WHERE message_id=?", [message_id])
        if trace:
            r = rows[0] if rows else {}
            trace.add("email_by_message_id", {"message_id": message_id},
                      f"{len(rows)} correo(s) · veredicto {r.get('verdict')} · SPF/DKIM/DMARC "
                      f"{r.get('spf')}/{r.get('dkim')}/{r.get('dmarc')}" if rows else "no encontrado")
        return rows

    def ai_session(self, session_id, trace: Trace = None):
        rows = self._rows("SELECT * EXCLUDE (ts) FROM ai_gateway WHERE session_id=? ORDER BY timestamp", [session_id])
        if trace:
            trace.add("ai_session", {"session_id": session_id}, f"{len(rows)} mensajes en la sesión")
        return rows

    def count_logs(self, source, where_sql, params=None, trace: Trace = None, label=""):
        n = self.con.execute(f"SELECT count(*) FROM {source} WHERE {where_sql}", params or []).fetchone()[0]
        if trace:
            trace.add("count_logs", {"source": source, "filter": label or where_sql}, f"{n} eventos")
        return n

    def intel(self, indicator, trace: Trace = None):
        ti = self._rows("SELECT * FROM ti_feed WHERE value=?", [indicator])
        geo = self._rows("SELECT * FROM geoip WHERE ip=?", [indicator])
        res = {"indicator": indicator, "tip": ti[0] if ti else None, "geo": geo[0] if geo else None}
        if trace:
            parts = []
            if ti:
                t = ti[0]
                parts.append(f"TIP: {t['reputation']} ({t['confidence']}) {t.get('malware_family') or ''}".strip())
            else:
                parts.append("TIP: sin coincidencias (desconocido ≠ limpio)")
            if geo:
                g = geo[0]
                tags = [k[3:] for k in ("is_tor", "is_vpn_provider", "is_hosting", "is_residential_proxy") if g[k] == "True"]
                parts.append(f"{g['country']} {g['as_org']}{' · ' + ','.join(tags) if tags else ''}")
            trace.add("intel", {"indicator": indicator}, " · ".join(parts))
        return res

    def sandbox(self, sha256, trace: Trace = None):
        r = self._rows("SELECT * FROM sandbox WHERE sha256=?", [sha256])
        if trace:
            trace.add("sandbox", {"sha256": sha256[:16] + "…"},
                      f"{r[0]['verdict']} ({r[0]['score']}) {r[0]['malware_family']}" if r else "sin informe")
        return r[0] if r else None

    def changes(self, text="", trace: Trace = None):
        out = [c for c in self._changes if text.lower() in json.dumps(c, ensure_ascii=False).lower()]
        if trace:
            trace.add("changes", {"q": text}, ", ".join(c["id"] for c in out) or "ningún cambio aprobado")
        return out

    def alerts_for_entity(self, value, around=None, hours=24, exclude_rules=(), trace: Trace = None):
        """Otras alertas que mencionan la entidad (usuario, host, IP, dominio)."""
        sql = "SELECT alert_id, ts, rule_id, rule_name, rule_severity FROM alerts WHERE raw ILIKE ?"
        params = [f"%{value}%"]
        if around is not None:
            sql += " AND ts BETWEEN ? AND ?"
            params += [around - timedelta(hours=hours), around + timedelta(hours=hours)]
        if exclude_rules:
            sql += f" AND rule_id NOT IN ({','.join('?' * len(exclude_rules))})"
            params += list(exclude_rules)
        rows = self._rows(sql + " ORDER BY ts", params)
        if trace:
            trace.add("alerts_for_entity", {"entity": value, "window": f"±{hours}h" if around else "todo"},
                      f"{len(rows)} alertas: " + ", ".join(sorted({r['rule_id'] for r in rows}))[:200])
        return rows
