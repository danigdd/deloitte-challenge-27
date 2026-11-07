"use client";

import { useEffect, useState } from "react";
import LayoutShell from "@/components/layout-shell";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { socApi } from "@/lib/api";

type Alert = {
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

function formatDate(iso: string) {
  return new Date(iso).toLocaleString("es-ES", {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    socApi
      .getAlerts()
      .then((data) => {
        if (!cancelled) {
          setTotal(data.total);
          setAlerts(data.items);
          setLoading(false);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setError("No se pudieron cargar las alertas");
          setLoading(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <LayoutShell
      title="Alertas"
      description="Alertas de seguridad detectadas por el agente SOC."
    >
      <div className="mb-6">
        <div className="flex items-center justify-between mb-3">
          <div>
            <p className="text-xs text-muted">Total de alertas</p>
            <p className="text-sm font-mono font-semibold text-text">
              {total}
            </p>
          </div>
          {error && (
            <div
              className="inline-flex items-center gap-2 rounded-sm border border-crit/30 bg-crit/10 px-3 py-1 text-xs text-crit"
            >
              <span className="h-3 w-3 rounded-full bg-crit"></span>
              {error}
            </div>
          )}
        </div>
      </div>

      {loading ? (
        <div className="flex h-[300px] items-center justify-center">
          <p className="text-xs text-muted">Cargando alertas…</p>
        </div>
      ) : alerts.length === 0 ? (
        <section
          className="border border-surface rounded-sm p-6 bg-surface flex flex-col items-center justify-center text-center min-h-[300px]"
        >
          <p className="text-xs text-muted">No hay alertas</p>
          <p className="text-xs font-mono text-muted mt-1">
            El agente aún no ha emitido alertas.
          </p>
        </section>
      ) : (
        <div className="overflow-x-auto border border-surface rounded-sm bg-surface">
          <table className="w-full text-xs border-collapse">
            <thead>
              <tr className="border-b border-surface">
                <th className="pb-3 font-mono text-muted font-medium">
                  ID
                </th>
                <th className="pb-3 font-mono text-muted font-medium">
                  Fecha
                </th>
                <th className="pb-3 font-mono text-muted font-medium">
                  Producto
                </th>
                <th className="pb-3 font-mono text-muted font-medium">
                  Regla
                </th>
                <th className="pb-3 font-mono text-muted font-medium">
                  Severidad
                </th>
                <th className="pb-3 font-mono text-muted font-medium">
                  Estado
                </th>
                <th className="pb-3 font-mono text-muted font-medium">
                  IP
                </th>
                <th className="pb-3 font-mono text-muted font-medium">
                  Acción
                </th>
                <th className="pb-3 font-mono text-muted font-medium">
                  MITRE
                </th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((a) => (
                <tr
                  key={a.alert_id}
                  className="border-t border-surface/50 hover:bg-surface/50 transition-colors"
                >
                  <td className="pb-2 font-mono text-text">
                    {a.alert_id}
                  </td>
                  <td className="pb-2 font-mono text-muted">
                    {formatDate(a.created_at)}
                  </td>
                  <td className="pb-2 font-mono text-text">
                    {a.source_product}
                  </td>
                  <td className="pb-2 text-text">{a.rule_name}</td>
                  <td className="pb-2">
                    <SeverityBadge severity={a.severity} />
                  </td>
                  <td className="pb-2 font-mono text-muted">
                    {a.status}
                  </td>
                  <td className="pb-2 font-mono text-muted">
                    {a.entities.ips[0] ?? "—"}
                  </td>
                  <td className="pb-2 font-mono text-muted">
                    {a.evidence.action}
                  </td>
                  <td className="pb-2 font-mono text-muted">
                    {a.mitre.technique_id} {a.mitre.technique}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </LayoutShell>
  );
}