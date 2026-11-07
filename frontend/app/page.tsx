import ProductPreview from "@/components/product-preview";
import { Button } from "@/components/ui/button";
import Link from "next/link";

const steps = [
  {
    id: "observe",
    title: "Observe",
    desc: "Events are ingested from logs, endpoints, and cloud telemetry across the infrastructure.",
  },
  {
    id: "detect",
    title: "Detect",
    desc: "The agent flags anomalous patterns and matches them against known adversary tactics.",
  },
  {
    id: "investigate",
    title: "Investigate",
    desc: "Related events are grouped into a structured incident with evidence and indicators of compromise.",
  },
  {
    id: "correlate",
    title: "Correlate",
    desc: "IOCs and alerts are linked across sources to surface potential attack chains.",
  },
  {
    id: "report",
    title: "Report",
    desc: "Findings, timelines, and dashboards are generated for analyst review and response.",
  },
];

export default function Home() {
  return (
    <main className="flex flex-col">
      <section className="relative pt-20 pb-24 px-4 md:pt-36 md:pb-36 lg:pt-48 lg:pb-48">
        <div className="mx-auto max-w-8xl">
          <div className="grid md:grid-cols-12 gap-8 md:gap-x-12 gap-y-16 items-start">
            <div className="md:col-span-5">
              <div className="inline-flex items-center gap-2 rounded-sm border border-surface px-3 py-1 text-xs font-mono text-accent mb-6">
                AI SOC Analyst · Agent
              </div>
              <h1 className="text-4xl md:text-5xl font-semibold tracking-tight leading-tight mb-6">
                Security events, investigated by an AI analyst.
              </h1>
              <p className="text-lg text-muted max-w-xl mb-10 leading-relaxed">
                Un agente que observa tus eventos de seguridad, detecta
                comportamiento sospechoso, investiga incidentes y genera
                hallazgos estructurados — para que tus analistas dediquen
                menos tiempo a triage y más a responder.
              </p>
              <div className="flex flex-col sm:flex-row gap-3">
                <Button asChild>
                  <Link href="/dashboard">Abrir dashboard</Link>
                </Button>
                <Button variant="outline" asChild>
                  <Link href="/investigation">Espacio de investigación</Link>
                </Button>
              </div>
            </div>
            <div className="md:col-span-7">
              <ProductPreview />
            </div>
          </div>
        </div>
      </section>

      <section className="border-y border-surface py-24 px-4 md:py-32">
        <div className="mx-auto max-w-8xl">
          <div className="mb-14">
            <h2 className="text-2xl font-semibold tracking-tight mb-2">El bucle de investigación</h2>
            <p className="text-sm text-muted">
              Cómo el agente gestiona un evento de seguridad, de la detección al
              informe.
            </p>
          </div>
          <ol className="flex flex-col gap-8 md:grid md:grid-cols-5 md:gap-10">
            {steps.map((step, i) => (
              <li key={step.id}>
                <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-sm border border-surface bg-surface font-mono text-xs font-semibold text-text">
                  {i + 1}
                </span>
                <h3 className="text-sm font-semibold mt-3 mb-1">{step.title}</h3>
                <p className="text-xs text-muted leading-relaxed">{step.desc}</p>
              </li>
            ))}
          </ol>
        </div>
      </section>

      <footer className="border-t border-surface bg-surface py-16 px-4 md:py-24">
        <div className="mx-auto max-w-8xl">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
            <div className="flex items-center gap-2">
              <span className="font-mono text-xs font-semibold tracking-wider text-accent">SOC</span>
              <span className="text-sm font-medium text-text">Analyst</span>
            </div>
            <p className="text-xs text-muted">
              Producto en fase temprana. Los datos se poblan automáticamente
              desde el agente de IA cuando el backend esté conectado.
            </p>
          </div>
          <nav className="mt-10 md:mt-0 flex flex-col md:flex-row gap-6 text-xs text-muted">
            <Link href="/" className="hover:text-accent focus-visible-ring">
              Producto
            </Link>
            <Link href="/dashboard" className="hover:text-accent focus-visible-ring">
              Dashboard
            </Link>
            <Link href="/alerts" className="hover:text-accent focus-visible-ring">
              Alertas
            </Link>
            <Link href="/investigation" className="hover:text-accent focus-visible-ring">
              Investigación
            </Link>
            <Link href="/reports" className="hover:text-accent focus-visible-ring">
              Informes
            </Link>
          </nav>
        </div>
      </footer>
    </main>
  );
}