/**
 * Capa de conexión con el backend de IA (Python).
 *
 * Tu equipo de backend debe exponer estos endpoints. Mientras tanto,
 * los componentes muestran estados vacíos y no inventan datos.
 */
const API_BASE = process.env.NEXT_PUBLIC_API_BASE || "http://localhost:8000";

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: {
      "Content-Type": "application/json",
      ...options.headers,
    },
    ...options,
  });
  if (!res.ok) {
    throw new Error(`API error ${res.status} for ${path}`);
  }
  return res.json();
}

export const socApi = {
  /** Métricas del panel de control (eventos, alertas, críticos, MTTR) */
  getOverview: () => request<{
    events24h: number;
    openAlerts: number;
    critical: number;
    meanTimeToTriage: string;
  }>("/api/overview"),

  /** Actividad de amenazas para el gráfico de área */
  getThreatActivity: () => request<{ label: string; value: number }[]>(
    "/api/threat-activity"
  ),

  /** Cola de incidentes */
  getIncidents: () => request<{
    id: string;
    title: string;
    severity: "low" | "medium" | "high" | "critical";
    status: string;
  }[]>("/api/incidents"),

  /** Alertas recientes */
  getAlerts: () => request<{
    time: string;
    event: string;
    source: string;
    severity: "low" | "medium" | "high" | "critical";
  }[]>("/api/alerts"),

  /** Actividad del agente */
  getAgentActivity: () => request<{ time: string; action: string }[]>(
    "/api/agent-activity"
  ),

  /** Timeline de investigación de un incidente */
  getInvestigationTimeline: (incidentId: string) =>
    request<{
      time: string;
      title: string;
      source: string;
      severity: "low" | "medium" | "high" | "critical";
    }[]>(`/api/investigations/${incidentId}/timeline`),

  /** IOCs de un incidente */
  getIOCs: (incidentId: string) =>
    request<{
      indicator: string;
      type: string;
      source: string;
      severity: "low" | "medium" | "high" | "critical";
    }[]>(`/api/investigations/${incidentId}/iocs`),

  /** Distribución de amenazas (donut) */
  getThreatDistribution: () => request<{
    label: string;
    value: number;
    color: string;
  }[]>("/api/reports/threat-distribution"),

  /** Desglose por severidad (barras) */
  getSeverityBreakdown: () => request<{
    label: string;
    value: number;
    color: string;
  }[]>("/api/reports/severity-breakdown"),

  /** Fuentes principales (tabla) */
  getTopSources: () => request<{
    source: string;
    events: number;
    severity: "low" | "medium" | "high" | "critical";
  }[]>("/api/reports/top-sources"),

  /** Envía una consulta al agente SOC (Python) */
  askAgent: (message: string) =>
    request<{ response: string; findings?: unknown[] }>("/api/agent/ask", {
      method: "POST",
      body: JSON.stringify({ message }),
    }),
};