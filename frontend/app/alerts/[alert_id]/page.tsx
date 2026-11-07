import { notFound } from "next/navigation";
import LayoutShell from "@/components/layout-shell";
import { SeverityBadge } from "@/components/ui/severity-badge";
import BackButton from "@/components/back-button";

export const instant = false;

type AlertUser = { upn: string; display_name: string };

type AlertDetail = {
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

type Triaje = {
  veredicto?: string;
  confianza?: string;
  severidad_recalculada?: string;
  resumen?: string;
  evidencias?: string[];
  accion_recomendada?: string;
};

type BackendResponse = {
  status?: string;
  alert_id?: string;
  triaje?: Triaje;
  alerta_original?: AlertDetail;
};

function formatDate(iso?: string) {
  if (!iso) return "";
  return new Date(iso).toLocaleString("es-ES", {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function getVeredictoBadge(veredicto?: string) {
  switch (veredicto) {
    case "true_positive":
      return "border-red-500/30 bg-red-500/10 text-red-400";
    case "false_positive":
      return "border-green-500/30 bg-green-500/10 text-green-400";
    case "benign_true_positive":
      return "border-blue-500/30 bg-blue-500/10 text-blue-400";
    default:
      return "border-surface bg-surface/50 text-muted";
  }
}

export default async function AlertDetailPage({
  params,
}: {
  params: Promise<{ alert_id: string }> | { alert_id: string };
}) {
  const { alert_id } =
    typeof params === "object" && !("then" in params) ? params : await params;

  const API_BASE = process.env.NEXT_PUBLIC_API_BASE || "http://127.0.0.1:5000";

  const res = await fetch(`${API_BASE}/api/alerts/${alert_id}`, {
    headers: { "Content-Type": "application/json" },
    cache: "no-store",
  });

  if (!res.ok) return notFound();

  const data: BackendResponse = await res.json();

  if (data.status === "error" || !data.alerta_original) return notFound();

  const alert = data.alerta_original;
  const triaje = data.triaje;

  return (
    <LayoutShell
      title={`Alerta ${data.alert_id ?? alert_id}`}
      description={(alert?.description || alert?.rule_name) ?? ""}
    >
      <div className="max-w-3xl mx-auto space-y-6">
        {/* CABECERA */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-2">
          <div>
            <h1 className="text-lg font-mono font-semibold text-text">
              {data.alert_id ?? alert_id}
            </h1>
            <p className="text-xs text-muted font-mono">
              {formatDate(alert?.created_at)} &bull;{" "}
              {alert?.source_product ?? "—"}
            </p>
          </div>
          <div className="flex items-center gap-2">
            {alert?.severity && <SeverityBadge severity={alert.severity} />}
            <span
              className={`px-2 py-0.5 rounded text-xs font-mono border ${
                alert?.status === "new"
                  ? "border-warn bg-warn/10 text-warn"
                  : alert?.status === "resolved"
                    ? "border-ok bg-ok/10 text-ok"
                    : "border-surface bg-surface/50 text-muted"
              }`}
            >
              {alert?.status ?? "—"}
            </span>
          </div>
        </div>

        {/* TRIAJE DE LA IA */}
        {triaje && (
          <section className="border border-primary/40 rounded-sm bg-surface p-4">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-xs font-mono font-bold text-primary uppercase">
                Triaje IA (Nivel 1)
              </h2>
              <span
                className={`px-2 py-0.5 text-xs font-mono rounded border uppercase font-bold ${getVeredictoBadge(
                  triaje.veredicto,
                )}`}
              >
                {triaje.veredicto?.replace(/_/g, " ") ?? "—"}
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mb-3">
              <div className="bg-surface/50 rounded p-2.5 border border-surface">
                <p className="text-xs text-muted font-mono">Confianza</p>
                <p className="text-sm text-text capitalize">
                  {triaje.confianza ?? "—"}
                </p>
              </div>
              <div className="bg-surface/50 rounded p-2.5 border border-surface">
                <p className="text-xs text-muted font-mono">
                  Severidad recalculada
                </p>
                <p className="text-sm text-text capitalize">
                  {triaje.severidad_recalculada ?? "—"}
                </p>
              </div>
            </div>

            {triaje.resumen && (
              <div className="mb-3">
                <p className="text-xs text-muted font-mono mb-1">Resumen:</p>
                <p className="text-xs text-text">{triaje.resumen}</p>
              </div>
            )}

            {triaje.evidencias && triaje.evidencias.length > 0 && (
              <div className="mb-3">
                <p className="text-xs text-muted font-mono mb-1">
                  Evidencias clave:
                </p>
                <ul className="list-disc list-inside space-y-1 text-xs text-text font-mono">
                  {triaje.evidencias.map((ev, idx) => (
                    <li key={idx}>{ev}</li>
                  ))}
                </ul>
              </div>
            )}

            {triaje.accion_recomendada && (
              <div className="p-2 rounded bg-ok/5 border border-ok/20 text-xs text-ok font-mono">
                <span className="font-bold">Acción recomendada: </span>
                {triaje.accion_recomendada}
              </div>
            )}
          </section>
        )}

        {/* DESCRIPCIÓN */}
        {alert?.description && (
          <section className="border border-surface rounded-sm bg-surface p-4">
            <h2 className="text-xs font-mono font-semibold text-muted mb-2">
              Descripción
            </h2>
            <p className="text-sm text-text">{alert.description}</p>
          </section>
        )}

        {/* REGLA Y MITRE */}
        <section className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="border border-surface rounded-sm bg-surface p-4">
            <h2 className="text-xs font-mono font-semibold text-muted mb-2">
              Regla
            </h2>
            <p className="text-xs font-mono text-text">
              {alert?.rule_id ?? "—"}
            </p>
            <p className="text-sm text-text">{alert?.rule_name ?? "—"}</p>
          </div>
          <div className="border border-surface rounded-sm bg-surface p-4">
            <h2 className="text-xs font-mono font-semibold text-muted mb-2">
              MITRE ATT&CK
            </h2>
            {alert?.mitre ? (
              <>
                <p className="text-xs font-mono text-text">
                  {alert.mitre.technique_id ?? "—"} &bull;{" "}
                  {alert.mitre.technique ?? "—"}
                </p>
                <p className="text-xs text-muted">
                  {alert.mitre.tactic ?? "—"}
                </p>
              </>
            ) : (
              <p className="text-xs text-muted">Sin datos MITRE</p>
            )}
          </div>
        </section>

        {/* ENTIDADES */}
        {(alert?.entities?.users?.length ||
          alert?.entities?.domains?.length ||
          alert?.entities?.ips?.length ||
          alert?.entities?.urls?.length) && (
          <section className="border border-surface rounded-sm bg-surface p-4">
            <h2 className="text-xs font-mono font-semibold text-muted mb-3">
              Entidades
            </h2>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {alert?.entities?.users?.length ? (
                <div>
                  <h3 className="text-xs font-mono text-muted mb-1">
                    Usuarios
                  </h3>
                  <ul className="space-y-1">
                    {alert.entities.users.map((u) => (
                      <li key={u.upn} className="text-sm text-text font-mono break-all">
                        {u.display_name} ({u.upn})
                      </li>
                    ))}
                  </ul>
                </div>
              ) : null}
              {alert?.entities?.domains?.length ? (
                <div>
                  <h3 className="text-xs font-mono text-muted mb-1">
                    Dominios
                  </h3>
                  <ul className="space-y-1">
                    {alert.entities.domains.map((d) => (
                      <li key={d} className="text-sm text-text font-mono break-all">
                        {d}
                      </li>
                    ))}
                  </ul>
                </div>
              ) : null}
              {alert?.entities?.ips?.length ? (
                <div>
                  <h3 className="text-xs font-mono text-muted mb-1">IPs</h3>
                  <ul className="space-y-1">
                    {alert.entities.ips.map((ip) => (
                      <li key={ip} className="text-sm text-text font-mono break-all">
                        {ip}
                      </li>
                    ))}
                  </ul>
                </div>
              ) : null}
              {alert?.entities?.urls?.length ? (
                <div>
                  <h3 className="text-xs font-mono text-muted mb-1">URLs</h3>
                  <ul className="space-y-1">
                    {alert.entities.urls.map((url) => (
                      <li key={url} className="text-sm text-text font-mono break-all">
                        {url}
                      </li>
                    ))}
                  </ul>
                </div>
              ) : null}
            </div>
          </section>
        )}

        {/* EVIDENCIA */}
        {alert?.evidence && (
          <section className="border border-surface rounded-sm bg-surface p-4">
            <h2 className="text-xs font-mono font-semibold text-muted mb-3">
              Evidencia
            </h2>
            <div className="space-y-2 text-xs font-mono">
              {alert.evidence.message_id && (
                <div className="flex gap-2">
                  <span className="w-20 text-muted">Message ID</span>
                  <span className="text-text break-all">{alert.evidence.message_id}</span>
                </div>
              )}
              {alert.evidence.sender && (
                <div className="flex gap-2">
                  <span className="w-20 text-muted">Remitente</span>
                  <span className="text-text break-all">{alert.evidence.sender}</span>
                </div>
              )}
              {alert.evidence.subject && (
                <div className="flex gap-2">
                  <span className="w-20 text-muted">Asunto</span>
                  <span className="text-text break-all">{alert.evidence.subject}</span>
                </div>
              )}
              {alert.evidence.reported_by && (
                <div className="flex gap-2">
                  <span className="w-20 text-muted">Reportado por</span>
                  <span className="text-text break-all">
                    {alert.evidence.reported_by}
                  </span>
                </div>
              )}
              {alert.evidence.action && (
                <div className="flex gap-2">
                  <span className="w-20 text-muted">Acción</span>
                  <span className="text-text break-all">{alert.evidence.action}</span>
                </div>
              )}
            </div>
          </section>
        )}

        {/* EVENTOS Y RUNBOOK */}
        <section className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="border border-surface rounded-sm bg-surface p-4">
            <h2 className="text-xs font-mono font-semibold text-muted mb-2">
              Eventos relacionados
            </h2>
            {alert?.related_events?.length ? (
              <ul className="space-y-1 text-xs font-mono text-text">
                {alert.related_events.map((e) => (
                  <li key={e}>{e}</li>
                ))}
              </ul>
            ) : (
              <p className="text-xs text-muted">Sin eventos relacionados</p>
            )}
          </div>
          <div className="border border-surface rounded-sm bg-surface p-4">
            <h2 className="text-xs font-mono font-semibold text-muted mb-2">
              Runbook
            </h2>
            <p className="text-sm text-text font-mono">
              {alert?.runbook ?? "N/A"}
            </p>
          </div>
        </section>

        <div className="pt-4">
          <BackButton />
        </div>
      </div>
    </LayoutShell>
  );
}
