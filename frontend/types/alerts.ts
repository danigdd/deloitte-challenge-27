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
