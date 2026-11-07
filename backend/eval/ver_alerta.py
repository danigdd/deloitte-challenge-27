"""Muestra una alerta con su contexto, para triarla A MANO (sin IA).

Uso:
    python eval/ver_alerta.py ALR-20261012-011829
    python eval/ver_alerta.py ALR-20261012-011829 --logs edr_events WS-BCN-0412     # buscar más en un log (±24 h)

Enseña: la alerta, sus eventos relacionados, el equipo y el usuario (con RRHH), cambios aprobados,
reputación de IP/dominios/hashes y otras alertas de las mismas entidades en ±72 h.
Con eso decidís el veredicto esperado y lo apuntáis en eval/casos.jsonl.
"""
import argparse, json, os, sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from context import Ctx


def show(title, obj, limit=1500):
    print(f"\n── {title} " + "─" * max(0, 70 - len(title)))
    txt = obj if isinstance(obj, str) else json.dumps(obj, ensure_ascii=False, indent=1, default=str)
    print(txt if len(txt) <= limit else txt[:limit] + " …")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("alert_id")
    ap.add_argument("--logs", nargs=2, metavar=("FUENTE", "TEXTO"), help="buscar TEXTO en FUENTE ±24 h")
    args = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")
    ctx = Ctx()
    a = ctx.get_alert(args.alert_id)
    if not a:
        sys.exit("No existe esa alerta")
    ts = datetime.fromisoformat(a["created_at"].replace("Z", "+00:00")).replace(tzinfo=None)
    if args.logs:
        show(f"{args.logs[0]} con «{args.logs[1]}» ±24 h", ctx.search_logs(args.logs[0], args.logs[1], ts, 24, 60), 6000)
        return
    show("ALERTA", {k: a[k] for k in ("alert_id", "created_at", "rule_id", "rule_name", "severity", "runbook",
                                     "entities", "evidence", "mitre")}, 3000)
    for src, evs in ctx.get_related_events(a).items():
        show(f"Eventos relacionados · {src}", evs, 2500)
    ent = a.get("entities", {})
    for h in ent.get("hosts", []):
        x = ctx.get_asset(h.get("hostname") or h.get("ip"))
        if x:
            show(f"Equipo {x['hostname']}", {k: x[k] for k in ("criticality", "zone", "business_service", "owner_upn",
                                                               "internet_facing", "description", "vulnerabilities")})
    for u in ent.get("users", []):
        x = ctx.get_user(u.get("upn", ""))
        if x:
            show(f"Usuario {x['upn']}", {k: x[k] for k in ("title", "department", "account_type", "privileged", "vip",
                                                           "mfa_enabled", "hr_events") if k in x})
    for i in ent.get("ips", [])[:4] + ent.get("domains", [])[:3] + [f.get("sha256") for f in ent.get("files", []) if f.get("sha256")][:2]:
        r = ctx.intel(i)
        show(f"Reputación {i}", {"TIP": r["tip"], "GeoIP": r["geo"]}, 700)
    keys = [h.get("hostname") for h in ent.get("hosts", [])] + [u.get("upn", "").split("@")[0] for u in ent.get("users", [])]
    ch = [c for k in keys if k for c in ctx.changes(k)]
    show("Cambios aprobados que mencionan estas entidades", ch or "ninguno")
    for key in [h.get("hostname") for h in ent.get("hosts", [])] + [u.get("upn") for u in ent.get("users", [])] + ent.get("ips", [])[:2]:
        if key:
            al = [f"{r['ts']}  {r['alert_id']}  {r['rule_id']}  {r['rule_name']}" for r in ctx.alerts_for_entity(key, ts, 72)
                  if r["alert_id"] != a["alert_id"]]
            show(f"Otras alertas de {key} (±72 h)", "\n".join(al[:25]) or "ninguna", 3000)
    print("\nPara buscar más: python eval/ver_alerta.py", a["alert_id"], "--logs <fuente> <texto>")


if __name__ == "__main__":
    main()
