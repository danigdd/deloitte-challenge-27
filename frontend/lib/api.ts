const API_BASE = process.env.NEXT_PUBLIC_API_BASE || "http://127.0.0.1:5000";

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
  getOverview: () =>
    request<{
      events24h: number;
      openAlerts: number;
      critical: number;
      meanTimeToTriage: string;
    }>("/api/overview"),

  getThreatActivity: () =>
    request<{ label: string; value: number }[]>("/api/threat-activity"),

  getIncidents: () =>
    request<
      {
        id: string;
        title: string;
        severity: "low" | "medium" | "high" | "critical";
        status: string;
      }[]
    >("/api/incidents"),

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
};
