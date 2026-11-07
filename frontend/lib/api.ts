const API_BASE = process.env.NEXT_PUBLIC_API_BASE || "http://127.0.0.1:5000";

//generic typescript function that makes the request to our API
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

export function formatDate(iso?: string) {
  if (!iso) return "";
  return new Date(iso).toLocaleString("es-ES", {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export type Alert = {
  alert_id: string;
  created_at: string;
  source_product: string;
  rule_id: string;
  rule_name: string;
  severity: "low" | "medium" | "high" | "critical";
  status: string;
  mitre: {
    tactic: string;
    technique_id: string;
    technique: string;
  };
  description: string;
  entities: {
    ips: string[];
    urls: string[];
  };
  evidence: {
    rule_id: string;
    rule_msg: string;
    hits: number;
    action: string;
  };
  related_events: string[];
  runbook: string;
};

export type AlertUser = { upn: string; display_name: string };

export type AlertDetail = {
  alert_id?: string;
  id?: string;
  created_at?: string;
  source_product?: string;
  rule_id?: string;
  rule_name?: string;
  severity?: "low" | "medium" | "high" | "critical";
  status?: string;
  mitre?: { tactic?: string; technique_id?: string; technique?: string };
  description?: string;
  entities?: {
    users?: AlertUser[];
    domains?: string[];
    ips?: string[];
    urls?: string[];
  };
  evidence?: {
    message_id?: string;
    sender?: string;
    subject?: string;
    reported_by?: string;
    action?: string;
  };
  related_events?: string[];
  runbook?: string;
};

export type Triaje = {
  veredicto?: string;
  confianza?: string;
  severidad_recalculada?: string;
  resumen?: string;
  evidencias?: string[];
  accion_recomendada?: string;
};

export type BackendAlertResponse = {
  status?: string;
  alert_id?: string;
  triaje?: Triaje;
  alerta_original?: AlertDetail;
};

//use with await socApi.method
export const socApi = {
  //general SOC data
  getOverview: () =>
    request<{
      events24h: number;
      openAlerts: number;
      critical: number;
      meanTimeToTriage: string;
    }>("/api/overview"),

  //threat activity. retrieves an array of objects with each one with label (time) and value. mesures progress
  getThreatActivity: () =>
    request<{ label: string; value: number }[]>("/api/threat-activity"),

  //incidents with its id, title, severity and current status
  getIncidents: () =>
    request<
      {
        id: string;
        title: string;
        severity: "low" | "medium" | "high" | "critical";
        status: string;
      }[]
    >("/api/incidents"),

  //get alerts. retunrs total of alerts and an array with each one.
  // Each one has its identification (alert_id, created_at,...)
  // Severity and status
  // MITRE ATT&CK info (tactic, technique id, technique)
  // description
  // Similar entities with its ips and urls
  // Evidence that backs the detection
  // Related events
  // runbook (how to proceed)
  getAlerts: () =>
    request<{
      total: number;
      items: Array<{
        alert_id: string;
        created_at: string;
        source_product: string;
        rule_id: string;
        rule_name: string;
        severity: "low" | "medium" | "high" | "critical";
        status: string;
        mitre: {
          tactic: string;
          technique_id: string;
          technique: string;
        };
        description: string;
        entities: {
          ips: string[];
          urls: string[];
        };
        evidence: {
          rule_id: string;
          rule_msg: string;
          hits: number;
          action: string;
        };
        related_events: string[];
        runbook: string;
      }>;
    }>("/api/alerts"),

  getAgentActivity: () =>
    request<{ time: string; action: string }[]>("/api/agent-activity"),

  getInvestigationTimeline: (incidentId: string) =>
    request<
      {
        time: string;
        title: string;
        source: string;
        severity: "low" | "medium" | "high" | "critical";
      }[]
    >(`/api/investigations/${incidentId}/timeline`),

  getIOCs: (incidentId: string) =>
    request<
      {
        indicator: string;
        type: string;
        source: string;
        severity: "low" | "medium" | "high" | "critical";
      }[]
    >(`/api/investigations/${incidentId}/iocs`),

  getThreatDistribution: () =>
    request<
      {
        label: string;
        value: number;
        color: string;
      }[]
    >("/api/reports/threat-distribution"),

  getSeverityBreakdown: () =>
    request<
      {
        label: string;
        value: number;
        color: string;
      }[]
    >("/api/reports/severity-breakdown"),

  getTopSources: () =>
    request<
      {
        source: string;
        events: number;
        severity: "low" | "medium" | "high" | "critical";
      }[]
    >("/api/reports/top-sources"),

  askAgent: (message: string) =>
    request<{ response: string; findings?: unknown[] }>("/api/agent/ask", {
      method: "POST",
      body: JSON.stringify({ message }),
    }),

  // get a single alert by its alert_id (backend wrapper: status/triaje/alerta_original)
  getAlertById: (id: string) => request<BackendAlertResponse>(`/api/alerts/${id}`),
};
