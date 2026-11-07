"""Herramientas del agente en forma de comando, para usarlas desde Claude Code.

Claude Code solo tiene permiso para ejecutar ESTE script (no duckdb, ni otros comandos):
    python tools_cli.py <herramienta> --clave valor ...

Ejemplos:
    python tools_cli.py get_asset --key WS-BCN-1770
    python tools_cli.py get_user --key marta.puig@tarvia.example
    python tools_cli.py search_logs --source edr_events --text WS-BCN-1770 --around 2026-10-09T09:31:10Z --hours 24
    python tools_cli.py get_events --source proxy --event_ids PRX-0211359,PRX-0211360
    python tools_cli.py alerts_for_entity --entity marta.puig@tarvia.example --around 2026-10-09T09:31:10Z --hours 72
    python tools_cli.py intel --indicator aplihartom.com
    python tools_cli.py sandbox --sha256 6f395de6...
    python tools_cli.py changes --q WMS01

Todo es de solo lectura. La salida va envuelta en <datos_no_confiables>. Si la variable
TRIAGE_TRACE_FILE está definida, cada llamada se registra ahí (la traza del dashboard).
"""
import json, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from context import Ctx, Trace


def parse(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__); sys.exit(0)
    tool, args, i = argv[0], {}, 1
    while i < len(argv):
        k = argv[i].lstrip("-")
        v = argv[i + 1] if i + 1 < len(argv) else ""
        args[k] = v; i += 2
    if "event_ids" in args:
        args["event_ids"] = [x.strip() for x in args["event_ids"].split(",") if x.strip()]
    for k in ("hours", "limit"):
        if k in args:
            args[k] = int(args[k])
    return tool, args


def main():
    from agent import run_tool          # misma implementación que el agente por API
    tool, args = parse(sys.argv[1:])
    if tool == "submit_triage":
        print("submit_triage no es un comando: devuelve el JSON final como respuesta."); return
    ctx, tr = Ctx(), Trace()
    out = run_tool(ctx, tr, tool, args)
    trace_file = os.getenv("TRIAGE_TRACE_FILE")
    if trace_file:
        with open(trace_file, "a", encoding="utf-8") as f:
            for s in tr.steps:
                f.write(json.dumps(s, ensure_ascii=False, default=str) + "\n")
    sys.stdout.reconfigure(encoding="utf-8")
    print(out)


if __name__ == "__main__":
    main()
