"""Evalúa el sistema contra casos reales del dataset con veredicto esperado.

Uso (desde la carpeta del proyecto):
  python eval/run_eval.py                       # sistema completo: prefiltro y, si no cierra, agente
  python eval/run_eval.py --agent-only          # fuerza el agente en todos (mide el prompt)
  python eval/run_eval.py --provider mock       # prueba sin API

Ejecutadlo cada vez que cambiéis el prompt: si baja el acierto, el cambio empeora.
Escribe eval/resultados.md, útil para enseñarlo en la defensa.
"""
import argparse, json, os, sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import store
from agent import make_llm, triage
from context import Ctx
from prefilter import Prefilter

HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--provider", default=os.getenv("TRIAGE_PROVIDER", "anthropic"))
    ap.add_argument("--agent-only", action="store_true")
    args = ap.parse_args()
    ctx = Ctx()
    pf = Prefilter(ctx)
    cases = [json.loads(l) for l in open(os.path.join(HERE, "casos.jsonl"), encoding="utf-8")]
    con = store.connect()
    rows, ok_v, ok_e, ok_inj, n_inj = [], 0, 0, 0, 0
    for c in cases:
        a = ctx.get_alert(c["alert_id"])
        t0 = time.time()
        d = pf.decide(a)
        if d.disposition != "agent" and not args.agent_only:
            who, verdict, sev, esc, inj = "prefiltro", d.verdict, d.severity, False, bool(d.injection)
        else:
            llm = make_llm(args.provider)
            try:
                ticket, tr = triage(ctx, [a], llm, [d.route_reason] if d.route_reason else [])
                store.save_ticket(con, ticket, "eval", tr.steps, a["created_at"], llm.model, llm.tin, llm.tout)
                con.commit()
                who, verdict, sev = f"agente ({llm.model})", ticket["verdict"], ticket["severity"]
                esc, inj = ticket["escalation"]["escalate"], bool(ticket.get("_injection_observed"))
            except Exception as e:      # un caso roto no detiene la evaluación: cuenta como fallo
                print(f"  ⚠ error en {c['alert_id']}: {type(e).__name__}: {str(e)[:200]}")
                who, verdict, sev, esc, inj = f"agente ({llm.model}) · ERROR", "error", "-", None, False
        exp = c["expected_verdict"] if isinstance(c["expected_verdict"], list) else [c["expected_verdict"]]
        v_ok, e_ok = verdict in exp, esc == c["expected_escalate"]
        ok_v += v_ok; ok_e += e_ok
        if c.get("expect_injection"):
            n_inj += 1; ok_inj += inj
        rows.append((c["alert_id"], who, "/".join(exp), verdict, sev, c["expected_escalate"], esc, v_ok and e_ok,
                     c.get("uncertain", False), round(time.time() - t0, 1), c["why"]))
        print(f"{'✓' if v_ok and e_ok else '✗'} {c['alert_id']}  {verdict:22s} {sev:13s} esc={esc!s:5}  [{who}]")

    n = len(cases)
    summary = (f"Veredicto correcto: {ok_v}/{n} ({ok_v / n:.0%}) · Escalado correcto: {ok_e}/{n} ({ok_e / n:.0%})"
               + (f" · Inyección detectada: {ok_inj}/{n_inj}" if n_inj else ""))
    print("\n" + summary)
    with open(os.path.join(HERE, "resultados.md"), "w", encoding="utf-8") as f:
        f.write(f"# Evaluación del triaje ({args.provider}{', solo agente' if args.agent_only else ''})\n\n{summary}\n\n")
        f.write("| Alerta | Quién decide | Esperado | Obtenido | Severidad | Escalar esp./obt. | OK | Tiempo (s) | Caso |\n")
        f.write("|---|---|---|---|---|---|---|---|---|\n")
        for r in rows:
            f.write(f"| {r[0]} | {r[1]} | {r[2]} | {r[3]} | {r[4]} | {r[5]}/{r[6]} | {'✓' if r[7] else '✗'}"
                    f"{' (etiqueta dudosa)' if r[8] else ''} | {r[9]} | {r[10]} |\n")


if __name__ == "__main__":
    main()
