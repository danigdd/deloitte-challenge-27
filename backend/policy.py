"""Política del SOC de Tarvia traducida a código (01_contexto/politica_soc.md y empresa_tarvia.md).

Todo lo que aquí se decide es determinista y reproducible: el LLM no calcula la severidad,
solo aporta los factores (ejecución confirmada, bloqueo, etc.) y esta función la aplica.
"""
import re
from datetime import datetime
from zoneinfo import ZoneInfo

MADRID = ZoneInfo("Europe/Madrid")
UTC = ZoneInfo("UTC")

SEVERITIES = ["informational", "low", "medium", "high", "critical"]
CRITICALITY = ["Baja", "Media", "Alta", "Crítica"]

# Matriz del apartado 2: fila = severidad de la regla, columna = criticidad del activo/identidad
MATRIX = {
    "informational": ["informational", "informational", "low", "low"],
    "low":           ["informational", "low", "low", "medium"],
    "medium":        ["low", "medium", "medium", "high"],
    "high":          ["medium", "high", "high", "critical"],
    "critical":      ["high", "critical", "critical", "critical"],
}

SLA = {  # apartado 3
    "critical": "15 min · llamar a N2 de guardia · avisar a Responsable SOC y CISO",
    "high": "30 min · N2 en la misma jornada · avisar a Responsable SOC",
    "medium": "4 h · escalar si hay indicios de compromiso",
    "low": "24 h · sin escalado",
    "informational": "revisión en lote diaria",
}


def final_severity(rule_sev: str, criticality: str, up: list[str] = (), down: list[str] = (),
                   authorized: bool = False) -> tuple[str, str]:
    """Aplica la matriz y los ajustes. Devuelve (severidad, explicación legible)."""
    col = CRITICALITY.index(criticality) if criticality in CRITICALITY else 1
    base = MATRIX[rule_sev][col]
    why = f"Regla {rule_sev} × activo/identidad {criticality} = {base}"
    if authorized:
        sev = "informational" if base in ("informational", "low", "medium") else "low"
        return sev, why + f"; actividad autorizada → {sev} (política §2)"
    delta = (1 if up else 0) - (1 if down else 0)   # máximo un nivel en total
    sev = SEVERITIES[max(0, min(4, SEVERITIES.index(base) + delta))]
    if up:
        why += f"; +1 por {', '.join(up)}"
    if down:
        why += f"; −1 por {', '.join(down)}"
    if delta:
        why += f" → {sev}"
    return sev, why


def identity_criticality(user: dict | None) -> tuple[str, list[str]]:
    """Criticidad de una identidad y motivos de ajuste +1.
    Supuesto del equipo (la política no lo fija): cuenta de servicio privilegiada = Crítica,
    admin/privilegiada/VIP = Alta, resto = Media."""
    if not user:
        return "Media", []
    up = []
    if user.get("vip") == "True":
        up.append("identidad VIP")
    if user.get("privileged") == "True":
        up.append("identidad privilegiada")
    if user.get("account_type") == "service" and user.get("privileged") == "True":
        return "Crítica", up
    if up or user.get("account_type") == "admin":
        return "Alta", up
    return "Media", up


def max_criticality(*values: str) -> str:
    vals = [v for v in values if v in CRITICALITY]
    return max(vals, key=CRITICALITY.index) if vals else "Media"


# ---- Reglas internas de empresa_tarvia.md / calendario_cambios.csv -----------------------
PENTEST_IPS = {"192.0.2.10", "192.0.2.11", "192.0.2.12"}           # CHG-2026-1042
PENTEST_WINDOW = ("2026-10-08 08:00", "2026-10-10 18:00")            # hora local
SCCM_WINDOW_LOCAL = (8, 10)                                          # CHG-2026-1031
NESSUS_HOST = "NESSUS01"                                             # miércoles 01:00-05:00
OT_ALLOWED = {"ENG-WS01", "WMS01"}
ADM_ALLOWED_SOURCE = "JUMP01"
APPROVED_FLOW_GESTORIA = "asesoria@gestoria-pons.example"           # FLUJO-0007


def to_local(ts) -> datetime:
    if isinstance(ts, str):
        ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    return ts.astimezone(MADRID)


def in_local_window(ts, start: str, end: str) -> bool:
    t = to_local(ts).replace(tzinfo=None)
    return datetime.fromisoformat(start) <= t <= datetime.fromisoformat(end)


# ---- Texto escrito por el atacante ------------------------------------------------------
# Asuntos, cuerpos de correo, prompts de Vela o descripciones de servicios pueden contener
# instrucciones dirigidas a sistemas automáticos. El prefiltro NUNCA cierra una alerta que
# las contenga y el agente LLM las recibe marcadas como datos no confiables.
# Fuertes: intentan manipular al sistema o esconder texto. Nunca aparecen en uso legítimo.
_STRONG = [
    r"display\s*:\s*none", r"font-size\s*:\s*0", r"<!--",
    r"(clasificar|clasifica|marcar|marca)\s+(como|este)", r"false[_ ]positive", r"no escalar",
    r"(sistema|clasificador|agente|analista)\s+(automatizado|de seguridad|ia)",
    r"system prompt|prompt de sistema|instrucciones (anteriores|del sistema)",
    r"system override|modo desarrollador|developer mode", r"aprobado por (el )?(equipo )?soc",
]
# Débiles: frecuentes en clientes que se corrigen («ignora lo anterior, era la talla L»).
_WEAK = [r"ignor(a|e|ar)\s+(las|todas|previous|all|lo anterior)", r"olvida", r"no hagas caso"]
_INJ_STRONG = re.compile("|".join(_STRONG), re.IGNORECASE)
_INJ_ALL = re.compile("|".join(_STRONG + _WEAK), re.IGNORECASE)


def injection_hits(*texts, strong_only: bool = False) -> list[str]:
    rx = _INJ_STRONG if strong_only else _INJ_ALL
    hits = []
    for t in texts:
        if t:
            hits += [m.group(0) for m in rx.finditer(str(t))]
    return sorted(set(h.lower() for h in hits))
