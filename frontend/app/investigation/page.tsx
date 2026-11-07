import LayoutShell from "@/components/layout-shell";

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

export default function InvestigationPage() {
  return (
    <LayoutShell
      title="Investigación"
      description="Espacio de trabajo para investigar incidentes y revisar hallazgos del agente."
    >
      <div className="grid gap-6 md:grid-cols-12">
        <div className="col-span-12 lg:col-span-4">
          <section className="border border-surface rounded-sm p-5 bg-surface sticky top-24">
            <h3 className="text-sm font-semibold mb-4">Contexto del incidente</h3>
            <dl className="space-y-4 text-xs">
              <div className="grid grid-cols-2 gap-x-4 gap-y-2">
                <dt className="text-muted font-mono">ID de incidente</dt>
                <dd className="text-text font-mono">—</dd>
                <dt className="text-muted font-mono">Estado</dt>
                <dd className="text-text font-mono">—</dd>
                <dt className="text-muted font-mono">Severidad</dt>
                <dd className="text-text font-mono">—</dd>
                <dt className="text-muted font-mono">Detectado</dt>
                <dd className="text-text font-mono">—</dd>
                <dt className="text-muted font-mono">Fuente</dt>
                <dd className="text-text font-mono">—</dd>
                <dt className="text-muted font-mono">Asignado a</dt>
                <dd className="text-text font-mono">—</dd>
              </div>
            </dl>

            <section className="mt-8 border border-surface rounded-sm p-4 bg-surface-2">
              <h4 className="text-xs font-semibold text-text mb-3">Resumen</h4>
              <p className="text-xs text-muted leading-relaxed">
                El resumen se generará automáticamente una vez el agente
                procese un incidente.
              </p>
            </section>
          </section>
        </div>

        <div className="col-span-12 lg:col-span-8">
          <EmptyState
            title="Línea de tiempo de eventos"
            hint="Los eventos correlacionados por el agente aparecerán aquí ordenados por tiempo."
          />

          <div className="grid gap-6 mt-6 md:grid-cols-2">
            <EmptyState
              title="Indicadores de compromiso (IOCs)"
              hint="IPs, procesos, archivos y dominios sospechosos identificados."
            />

            <EmptyState
              title="Hallazgos del agente"
              hint="Hipótesis, evidencia y acciones recomendadas."
            />
          </div>
        </div>
      </div>
    </LayoutShell>
  );
}