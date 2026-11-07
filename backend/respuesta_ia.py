"""Puente entre el sistema de triaje y el backend del dashboard.

Devuelve el resultado en el formato `resultado_ia` que usa el frontend, más unos campos extra
(pasos, acciones con aprobación, escalado...) que el frontend puede ir usando cuando quiera.

USO DESDE EL BACKEND (Python)
    from respuesta_ia import resultado_guardado, triar_alerta, cola

    respuesta_ia = resultado_guardado("ALR-20261009-011791")   # rápido: lo ya triado (None si no hay)
    respuesta_ia = triar_alerta("ALR-20261009-011791")         # lanza el triaje ahora (prefiltro y, si hace falta, IA)
    respuesta_ia = triar_alerta(alerta_dict)                   # una alerta NUEVA en JSON (p. ej. las de la defensa)
    lista = cola(limit=50, solo="agent")                       # cola de alertas con su estado

USO DESDE LA TERMINAL
    python respuesta_ia.py ALR-20261009-011791                 # resultado guardado (o lo tría si no existe)
    python respuesta_ia.py ALR-20261009-011791 --nuevo         # fuerza un triaje nuevo
    python respuesta_ia.py --archivo alertas_defensa.jsonl     # tría un fichero de alertas nuevas (defensa)
    python respuesta_ia.py --exportar resultados_ia.json       # todo lo triado por la IA en un JSON {alert_id: resultado}
    python respuesta_ia.py --exportar r.json --basico          # solo los 6 campos del formato acordado

El proveedor de IA se elige con TRIAGE_PROVIDER (openai para el LLM de la UAB, claude_code, mock...).
"""
import json, os, sqlite3, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import store

SEV_ES = {"informational": "baja", "low": "baja", "medium": "media", "high": "alta", "critical": "critica"}
ACCION_ES = {"close": "Cerrar el ticket", "purge_email": "Purgar el correo de los buzones", "block_ioc": "Bloquear el indicador",
             "revoke_sessions": "Revocar sesiones", "reset_password": "Forzar cambio de contraseña",
             "isolate_host": "Aislar el equipo", "disable_user": "Deshabilitar la cuenta", "disable_access_key": "Desactivar la clave de acceso",
             "notify": "Avisar", "monitor": "Vigilar", "full_scan": "Escaneo completo", "tune_rule": "Ajustar la regla de detección"}


# ---------------------------------------------------------------------------------------
def _confianza(c: float) -> str:
    return "alta" if c >= 0.8 else "media" if c >= 0.5 else "baja"


def _pasos(trace: list) -> list:
    """Traza simplificada para pintar «qué hizo la IA» paso a paso."""
    tipo = {"read": "lectura", "query": "consulta", "check": "comprobación", "thought": "razonamiento", "policy": "política"}
    out = []
    for s in trace or []:
        p = {"tipo": tipo.get(s.get("kind"), s.get("kind")), "herramienta": s.get("tool"),
             "parametros": s.get("args") or {}, "resultado": str(s.get("result", ""))}
        if s.get("kind") == "check":
            p["ok"] = bool(s.get("passed"))
        out.append(p)
    return out


def a_formato_frontend(ticket: dict, trace: list, origen: str, alert_id: str) -> dict:
    acciones = [{"accion": a["action"], "accion_texto": ACCION_ES.get(a["action"], a["action"]), "objetivo": a["target"],
                 "requiere_aprobacion": a["requires_approval"], "justificacion": a.get("justification", "")}
                for a in ticket.get("recommended_actions", [])]
    texto_acc = "; ".join(f"{x['accion_texto']}: {x['objetivo']}" + (" (requiere aprobación)" if x["requiere_aprobacion"] else "")
                          for x in acciones) or "Sin acciones"
    esc = ticket.get("escalation", {})
    return {
        # ---- formato acordado con el frontend ----
        "veredicto": ticket["verdict"],                     # + "needs_more_info" cuando la IA no puede concluir
        "confianza": _confianza(ticket.get("confidence", 0)),
        "severidad_recalculada": SEV_ES.get(ticket["severity"], ticket["severity"]),
        "resumen": f"{ticket['title']}. {ticket.get('summary', '')}".strip(),
        "evidencias": [f"{e.get('finding', '')} ({e.get('source', '')} {e.get('event_id', '')})".strip()
                       for e in ticket.get("evidence", [])],
        "accion_recomendada": texto_acc,
        # ---- extra: para la demo (qué consultó, dónde decide la persona) ----
        "alert_id": alert_id,
        "ticket_id": ticket["ticket_id"],
        "alertas_agrupadas": ticket.get("alert_ids", [alert_id]),
        "titulo": ticket["title"],
        "quien_decide": "Prefiltro determinista (reglas de la política)" if origen == "prefilter" else "Agente IA",
        "confianza_num": ticket.get("confidence", 0),
        "severidad_exacta": ticket["severity"],             # informational | low | medium | high | critical
        "severidad_explicacion": ticket.get("severity_rationale", ""),
        "escalar": bool(esc.get("escalate")),
        "escalar_a": esc.get("to", ""),
        "motivo_escalado": esc.get("reason", ""),
        "acciones": acciones,                               # botón aprobar/rechazar si requiere_aprobacion
        "preguntas_abiertas": ticket.get("open_questions", []),
        "mitre": ticket.get("mitre", []),
        "pasos": _pasos(trace),
        "tiempo_segundos": ticket.get("triage_seconds", 0),
    }


# ---------------------------------------------------------------------------------------
def resultado_guardado(alert_id: str):
    """Último resultado guardado para la alerta (agente > evaluación > prefiltro). None si no hay ninguno."""
    con = sqlite3.connect(store.DB)
    row = con.execute("""SELECT t.ticket_json, t.trace, t.origin FROM tickets t JOIN ticket_alerts ta USING (ticket_id)
                         WHERE ta.alert_id = ?
                         ORDER BY (t.model = 'mock'),                       -- los simulados, solo si no hay otro
                                  CASE t.origin WHEN 'agent' THEN 0 WHEN 'eval' THEN 1 ELSE 2 END,
                                  t.rowid DESC LIMIT 1""", (alert_id,)).fetchone()
    if not row:
        return None
    return a_formato_frontend(json.loads(row[0]), json.loads(row[1] or "[]"), row[2], alert_id)


def triar_alerta(alerta, provider: str = None, forzar_ia: bool = False):
    """Tría una alerta (ID existente o dict de una alerta nueva) y guarda el resultado en triage.db."""
    from context import Ctx
    from prefilter import Prefilter
    from run_prefilter import group_ticket
    from agent import make_llm, triage
    ctx = Ctx()
    a = ctx.get_alert(alerta) if isinstance(alerta, str) else alerta
    if a is None:
        raise ValueError(f"No existe la alerta {alerta}")
    con = store.connect()
    d = Prefilter(ctx).decide(a)
    store.save_prefilter(con, a, d)
    if d.disposition != "agent" and not forzar_ia:
        t = group_ticket(f"{d.group_key}:{a['alert_id']}", [d], {a["alert_id"]: a})
        store.save_ticket(con, t, "prefilter", d.trace, a["created_at"])
        con.commit()
        return a_formato_frontend(t, d.trace, "prefilter", a["alert_id"])
    llm = make_llm(provider or os.getenv("TRIAGE_PROVIDER", "openai"))
    ticket, tr = triage(ctx, [a], llm, [d.route_reason] if d.route_reason else [])
    store.save_ticket(con, ticket, "agent", tr.steps, a["created_at"], llm.model, llm.tin, llm.tout)
    con.commit()
    return a_formato_frontend(ticket, tr.steps, "agent", a["alert_id"])


def cola(limit: int = 100, solo: str = None):
    """Alertas con su decisión del prefiltro y, si existe, el ticket. solo = auto_close | human_batch | agent."""
    con = sqlite3.connect(store.DB)
    q = """SELECT p.alert_id, p.created_at, p.rule_id, p.rule_name, p.rule_severity, p.disposition, p.verdict,
                  p.severity, p.route_reason, t.ticket_id, t.verdict, t.severity, t.escalate, t.origin
           FROM prefilter p
           LEFT JOIN ticket_alerts ta ON ta.alert_id = p.alert_id
           LEFT JOIN tickets t ON t.ticket_id = ta.ticket_id"""
    q += " WHERE p.disposition = ?" if solo else ""
    q += " ORDER BY p.created_at DESC LIMIT ?"
    rows = con.execute(q, ([solo] if solo else []) + [limit]).fetchall()
    out, seen = [], set()
    for r in rows:
        if r[0] in seen:
            continue
        seen.add(r[0])
        out.append({"alert_id": r[0], "fecha": r[1], "regla": r[2], "nombre_regla": r[3], "severidad_regla": r[4],
                    "destino": r[5], "veredicto": r[10] or r[6], "severidad": SEV_ES.get(r[11] or r[7] or "", None),
                    "escalar": bool(r[12]) if r[12] is not None else None, "triado_por": r[13], "motivo": r[8]})
    return out


BASICO = ("veredicto", "confianza", "severidad_recalculada", "resumen", "evidencias", "accion_recomendada")


def exportar(ruta: str = "resultados_ia.json", solo_basico: bool = False, incluir_prefiltro: bool = False) -> int:
    """Exporta todos los resultados triados a un JSON {alert_id: resultado_ia}. Por defecto solo los de la IA."""
    con = sqlite3.connect(store.DB)
    q = "SELECT DISTINCT ta.alert_id FROM ticket_alerts ta JOIN tickets t USING (ticket_id)"
    q += " WHERE t.model <> 'mock'" + ("" if incluir_prefiltro else " AND t.origin IN ('agent', 'eval')")
    out = {}
    for (aid,) in con.execute(q).fetchall():
        r = resultado_guardado(aid)
        if r:
            out[aid] = {k: r[k] for k in BASICO} if solo_basico else r
    json.dump(out, open(ruta, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    return len(out)


# ---------------------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Resultado de triaje en el formato del frontend")
    ap.add_argument("alert_id", nargs="?")
    ap.add_argument("--nuevo", action="store_true", help="tría de nuevo aunque haya resultado guardado")
    ap.add_argument("--ia", action="store_true", help="pasa por la IA aunque el prefiltro pudiera cerrarla")
    ap.add_argument("--archivo", help="JSONL con alertas nuevas (una por línea)")
    ap.add_argument("--provider")
    ap.add_argument("--exportar", metavar="RUTA", help="exporta todo lo triado por la IA a un JSON {alert_id: resultado}")
    ap.add_argument("--basico", action="store_true", help="con --exportar: solo los 6 campos del formato acordado")
    ap.add_argument("--con-prefiltro", action="store_true", help="con --exportar: incluye también lo cerrado por reglas")
    args = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")
    if args.exportar:
        n = exportar(args.exportar, args.basico, args.con_prefiltro)
        print(f"{n} resultados exportados a {args.exportar}")
    elif args.archivo:
        alertas = [json.loads(l) for l in open(args.archivo, encoding="utf-8") if l.strip()]
        print(f"{len(alertas)} alertas en {args.archivo}")
        res = []
        for a in alertas:
            t0 = time.time()
            r = triar_alerta(a, args.provider, args.ia)
            res.append(r)
            print(f"  {a['alert_id']}  {r['veredicto']:22s} {r['severidad_exacta']:13s} {'ESCALAR' if r['escalar'] else '       '}"
                  f"  [{r['quien_decide'][:10]}, {time.time() - t0:.0f}s]  {r['titulo'][:60]}", flush=True)
        out = os.path.splitext(args.archivo)[0] + "_resultados.json"
        json.dump(res, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
        print(f"Resultados en {out}")
    elif args.alert_id:
        r = None if (args.nuevo or args.ia) else resultado_guardado(args.alert_id)
        r = r or triar_alerta(args.alert_id, args.provider, args.ia)
        print(json.dumps(r, ensure_ascii=False, indent=2))
    else:
        ap.print_help()
