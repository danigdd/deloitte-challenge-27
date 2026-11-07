"""Pasa el prefiltro por todas las alertas, correlaciona, agrupa en tickets y guarda en triage.db.

Uso:  python run_prefilter.py            (todas)
      python run_prefilter.py --dev      (solo la muestra de desarrollo de 150)
"""
import argparse, json, time
from collections import Counter, defaultdict

from context import Ctx
from prefilter import Prefilter, correlate
import store

SEV_ORDER = ["informational", "low", "medium", "high", "critical"]


def group_ticket(key, decs, alerts):
    """Un ticket por grupo (política §6: varias alertas del mismo patrón → un ticket)."""
    decs = sorted(decs, key=lambda d: alerts[d.alert_id]["created_at"])
    d0 = decs[0]
    sev = max((d.severity for d in decs), key=SEV_ORDER.index)
    n = len(decs)
    first, last = alerts[decs[0].alert_id]["created_at"], alerts[decs[-1].alert_id]["created_at"]
    rel = [e for d in decs[:5] for e in alerts[d.alert_id].get("related_events", [])[:2]]
    return {
        "ticket_id": "TKT-PF-" + key.replace(":", "-").replace("@", "_")[:60],
        "alert_ids": [d.alert_id for d in decs],
        "title": d0.title + (f" ({n} alertas)" if n > 1 else ""),
        "verdict": d0.verdict,
        "confidence": round(min(d.confidence for d in decs), 2),
        "severity": sev,
        "severity_rationale": d0.severity_rationale,
        "affected": {"users": [], "hosts": [], "business_services": [], "customers": []},
        "summary": f"{d0.title}. {n} alerta(s) entre {first[:16]} y {last[:16]} UTC. "
                   f"Decisión determinista del prefiltro basada en: {d0.basis}.",
        "evidence": [{"source": "related_events", "event_id": e, "finding": "evento de la alerta"} for e in rel],
        "enrichment": [],
        "mitre": sorted({alerts[d.alert_id]["mitre"]["technique_id"] for d in decs}),
        "recommended_actions": d0.recommended_actions,
        "executed_actions": [],
        "escalation": {"escalate": False, "to": "", "reason": ""},
        "open_questions": d0.open_questions,
        "triage_seconds": 0,
    }


def main(dev=False):
    t0 = time.time()
    ctx = Ctx()
    rows = ctx.con.execute("SELECT raw FROM alerts" + (" WHERE alert_id IN (SELECT alert_id FROM alerts_dev)" if dev else "")
                           + " ORDER BY ts").fetchall()
    alerts = {a["alert_id"]: a for a in (json.loads(r[0]) for r in rows)}
    pf = Prefilter(ctx)
    decisions = {aid: pf.decide(a) for aid, a in alerts.items()}
    t1 = time.time()
    reopened = correlate(alerts, decisions, ctx)

    con = store.connect()
    con.execute("DELETE FROM prefilter"); con.execute("DELETE FROM tickets WHERE origin='prefilter'")
    for aid, d in decisions.items():
        store.save_prefilter(con, alerts[aid], d)
    groups = defaultdict(list)
    for d in decisions.values():
        if d.disposition in ("auto_close", "human_batch"):
            groups[(d.disposition, d.group_key)].append(d)
    for (disp, key), decs in groups.items():
        t = group_ticket(key, decs, alerts)
        store.save_ticket(con, t, "prefilter", decs[0].trace, alerts[decs[0].alert_id]["created_at"])
        if disp == "human_batch":
            con.execute("UPDATE tickets SET status='pending_batch_review' WHERE ticket_id=?", (t["ticket_id"],))
    con.commit()

    # ---- Embudo ----
    disp = Counter(d.disposition for d in decisions.values())
    n = len(decisions)
    print(f"\nAlertas: {n:,}   (prefiltro {t1 - t0:.0f}s, correlación reabrió {reopened})")
    for k in ("auto_close", "human_batch", "agent"):
        print(f"  {k:12s} {disp[k]:>6,}  ({disp[k] / n:.1%})")
    print(f"Tickets generados por el prefiltro: {len(groups):,}")
    agent = [d for d in decisions.values() if d.disposition == "agent"]
    print(f"\nVan al agente ({len(agent)}), por regla:")
    for r, c in Counter(d.rule_id for d in agent).most_common():
        print(f"  {r:12s} {c}")
    print("\nMotivos:")
    for r, c in Counter(d.route_reason.split(':')[0] for d in agent).most_common():
        print(f"  {c:>4}  {r}")
    print("\nVeredictos de lo cerrado:", dict(Counter(d.verdict for d in decisions.values() if d.disposition != "agent")))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--dev", action="store_true")
    main(ap.parse_args().dev)
