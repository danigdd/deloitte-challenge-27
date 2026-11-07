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

export default function ReportsPage() {
  return (
    <LayoutShell
      title="Informes generados"
      description="Visualizaciones generadas a partir de los eventos procesados por el agente."
    >
      <div className="grid gap-6 md:grid-cols-12 lg:gap-8">
        <div className="col-span-12 lg:col-span-6 xl:col-span-4">
          <EmptyState
            title="Distribución de amenazas"
            hint="Gráfico de donut con la proporción de tipos de incidente."
          />
        </div>

        <div className="col-span-12 lg:col-span-6 xl:col-span-4">
          <EmptyState
            title="Desglose por severidad"
            hint="Barras con el volumen de alertas por nivel de severidad."
          />
        </div>

        <div className="col-span-12 lg:col-span-6 xl:col-span-4">
          <EmptyState
            title="Línea de tiempo de eventos"
            hint="Evolución temporal de eventos ingestados."
          />
        </div>

        <div className="col-span-12 lg:col-span-6 xl:col-span-4">
          <EmptyState
            title="Fuentes principales"
            hint="Tabla de orígenes con mayor volumen de eventos sospechosos."
          />
        </div>
      </div>
    </LayoutShell>
  );
}