"""
Ejemplo de backend Python para el SOC Analyst (FastAPI).

Instalación:
    pip install fastapi uvicorn

Ejecución:
    uvicorn backend_example:app --reload --port 8000

Este backend se conecta con el frontend Next.js a través de las rutas
en app/api/. Los datos son ejemplos — reemplázalos por tu lógica real
de detección, investigación y generación de informes.
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional

app = FastAPI(title="SOC Analyst Agent")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Modelos
# ---------------------------------------------------------------------------
class Overview(BaseModel):
    events24h: int
    openAlerts: int
    critical: int
    meanTimeToTriage: str


class ThreatActivityPoint(BaseModel):
    label: str
    value: int


class Incident(BaseModel):
    id: str
    title: str
    severity: str
    status: str


class Alert(BaseModel):
    time: str
    event: str
    source: str
    severity: str


class AgentAction(BaseModel):
    time: str
    action: str


class TimelineEvent(BaseModel):
    time: str
    title: str
    source: str
    severity: str


class IOC(BaseModel):
    indicator: str
    type: str
    source: str
    severity: str


class DonutSegment(BaseModel):
    label: str
    value: int
    color: str


class BarSeries(BaseModel):
    label: str
    value: int
    color: str


class SourceRow(BaseModel):
    source: str
    events: int
    severity: str


class AskRequest(BaseModel):
    message: str


class AskResponse(BaseModel):
    response: str
    findings: Optional[List[dict]] = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get("/api/overview", response_model=Overview)
def get_overview():
    """Métricas principales del dashboard."""
    return Overview(
        events24h=0,
        openAlerts=0,
        critical=0,
        meanTimeToTriage="—",
    )


@app.get("/api/threat-activity", response_model=List[ThreatActivityPoint])
def get_threat_activity():
    """Eventos por día para el gráfico de área."""
    return []


@app.get("/api/incidents", response_model=List[Incident])
def get_incidents():
    """Cola de incidentes abiertos."""
    return []


@app.get("/api/alerts", response_model=List[Alert])
def get_alerts():
    """Alertas recientes priorizadas."""
    return []


@app.get("/api/agent-activity", response_model=List[AgentAction])
def get_agent_activity():
    """Traza de acciones del agente SOC."""
    return []


@app.get("/api/investigations/{incident_id}/timeline", response_model=List[TimelineEvent])
def get_investigation_timeline(incident_id: str):
    """Línea de tiempo de eventos de un incidente."""
    return []


@app.get("/api/investigations/{incident_id}/iocs", response_model=List[IOC])
def get_iocs(incident_id: str):
    """Indicadores de compromiso de un incidente."""
    return []


@app.get("/api/reports/threat-distribution", response_model=List[DonutSegment])
def get_threat_distribution():
    """Distribución de tipos de amenaza (donut)."""
    return []


@app.get("/api/reports/severity-breakdown", response_model=List[BarSeries])
def get_severity_breakdown():
    """Volumen de alertas por severidad (barras)."""
    return []


@app.get("/api/reports/top-sources", response_model=List[SourceRow])
def get_top_sources():
    """Fuentes con más eventos sospechosos."""
    return []


@app.post("/api/agent/ask", response_model=AskResponse)
def ask_agent(req: AskRequest):
    """
    Envía una consulta al agente SOC.
    Aquí es donde conectarías tu lógica de IA (LLM, reglas, correlación, etc.).
    """
    return AskResponse(
        response="El agente aún no está conectado. Implementa tu lógica de IA aquí.",
        findings=[],
    )