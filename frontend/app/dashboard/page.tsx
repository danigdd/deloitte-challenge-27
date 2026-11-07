import LayoutShell from "@/components/layout-shell";
import Link from "next/link";

function EmptyState({
  title,
  hint,
}: {
  title: string;
  hint: string;
}) {
  return (
    <section className="border border-surface rounded-sm p-6 bg-surface flex flex-col items-center justify-center min-h-[200px]">
      <p className="text-xs text-muted">{title}</p>
      <p className="text-xs font-mono text-muted mt-1">{hint}</p>
    </section>
  );
}

export default function DashboardPage() {
  return (
    <LayoutShell
      title="Security overview"
      description="Events, alerts, and incident status across the infrastructure."
    >
      <div className="grid gap-6 md:grid-cols-12">
        <div className="col-span-12 grid grid-cols-2 sm:grid-cols-4 gap-4">
          <div className="border border-surface rounded-sm p-4 bg-surface flex flex-col items-center justify-center text-center">
            <p className="text-xs text-muted">Eventos (24h)</p>
            <p className="text-sm font-mono font-semibold text-text">—</p>
          </div>
          <div className="border border-surface rounded-sm p-4 bg-surface flex flex-col items-center justify-center text-center">
            <p className="text-xs text-muted">Alertas abiertas</p>
            <p className="text-sm font-mono font-semibold text-text">—</p>
          </div>
          <div className="border border-surface rounded-sm p-4 bg-surface flex flex-col items-center justify-center text-center">
            <p className="text-xs text-muted">Críticas</p>
            <p className="text-sm font-mono font-semibold text-text">—</p>
          </div>
          <div className="border border-surface rounded-sm p-4 bg-surface flex flex-col items-center justify-center text-center">
            <p className="text-xs text-muted">MTTR</p>
            <p className="text-sm font-mono font-semibold text-text">—</p>
          </div>
        </div>

        <div className="col-span-12 lg:col-span-8">
          <EmptyState
            title="Actividad de amenazas"
            hint="El gráfico se rellenará cuando el agente comience a ingestar eventos."
          />
        </div>

        <div className="col-span-12 lg:col-span-4">
          <EmptyState
            title="Cola de incidentes"
            hint="Los incidentes detectados por el agente aparecerán aquí."
          />
        </div>

        <div className="col-span-12" id="alerts">
          <EmptyState
            title="Alertas recientes"
            hint="Lista de alertas priorizadas por el agente."
          />
        </div>

        <div className="col-span-12" id="agent">
          <EmptyState
            title="Actividad del agente"
            hint="Traza de acciones ejecutadas por el agente SOC."
          />
        </div>
      </div>
    </LayoutShell>
  );
}