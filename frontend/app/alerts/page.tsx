"use client";

import { useEffect, useState, ReactNode } from "react";
import { useRouter } from "next/navigation";
import LayoutShell from "@/components/layout-shell";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { socApi, Alert, formatDate } from "@/lib/api";

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [currentPage, setCurrentPage] = useState(1);
  const ITEMS_PER_PAGE = 50;
  const router = useRouter();

  const realTotal = alerts.length;
  const totalPages = Math.ceil(realTotal / ITEMS_PER_PAGE) || 1;

  // Example use. If we have 100 alerts and in page 1, we will get 0-50 alerts (1-1) * 50 = 0, 1 * 50 = 50.
  const paginatedAlerts = alerts.slice(
    (currentPage - 1) * ITEMS_PER_PAGE,
    currentPage * ITEMS_PER_PAGE,
  );

  const goToPage = (page: number) => {
    //We filter invalid pages
    const p = Math.max(1, Math.min(page, totalPages));
    setCurrentPage(p);
    router.replace(`?page=${p}`, { scroll: false });
  };

  //CALL ALERTS SOCAPI
  useEffect(() => {
    //we prevent api response if user starts the request and leaves before the response is received
    let cancelled = false;

    //CRITICAL: we call our getAlerts socAPI method, we wait for the promise with then((data) => )
    socApi
      .getAlerts()
      .then((data) => {
        //we save the alerts from our method
        if (!cancelled) {
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

  //change page from params
  useEffect(() => {
    const params = new URLSearchParams(window.location.search); //get current params
    const pageParam = params.get("page");
    const page = pageParam ? parseInt(pageParam, 10) : NaN;

    const syncFromUrl = () => {
      if (!isNaN(page) && page >= 1) {
        setCurrentPage(Math.min(page, totalPages));
      }
    };

    syncFromUrl();
  }, [totalPages]); //when total pages changes

  //same thing with browser buttons
  useEffect(() => {
    const onPopState = () => {
      const params = new URLSearchParams(window.location.search);
      const pageParam = params.get("page");
      const page = pageParam ? parseInt(pageParam, 10) : NaN;
      if (!isNaN(page) && page >= 1 && page <= totalPages) {
        setCurrentPage(page);
      }
    };
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, [totalPages]);

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
              {realTotal}
            </p>
          </div>
          {error && (
            <div className="inline-flex items-center gap-2 rounded-sm border border-crit/30 bg-crit/10 px-3 py-1 text-xs text-crit">
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
        <section className="border border-surface rounded-sm p-6 bg-surface flex flex-col items-center justify-center text-center min-h-[300px]">
          <p className="text-xs text-muted">No hay alertas</p>
          <p className="text-xs font-mono text-muted mt-1">
            El agente aún no ha emitido alertas.
          </p>
        </section>
      ) : (
        <>
          <div className="overflow-x-auto border border-surface rounded-sm bg-surface">
            <table className="w-full text-xs border-collapse">
              <thead>
                <tr className="border-b border-surface">
                  <th className="pb-3 font-mono text-muted font-medium">ID</th>
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
                  <th className="pb-3 font-mono text-muted font-medium">IP</th>
                  <th className="pb-3 font-mono text-muted font-medium">
                    Acción
                  </th>
                  <th className="pb-3 font-mono text-muted font-medium">
                    MITRE
                  </th>
                </tr>
              </thead>
              <tbody>
                {paginatedAlerts.map((a) => (
                  <tr
                    key={a.alert_id}
                    onClick={() => router.push(`/alerts/${a.alert_id}`)}
                    className="border-t border-surface/50 hover:bg-surface/100 transition-colors cursor-pointer"
                  >
                    <td className="pb-2 font-mono text-text">{a.alert_id}</td>
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
                    <td className="pb-2 font-mono text-muted">{a.status}</td>
                    <td className="pb-2 font-mono text-muted">
                      {a.entities?.ips?.[0] ?? "—"}
                    </td>
                    <td className="pb-2 font-mono text-muted">
                      {a.evidence?.action ?? "—"}
                    </td>
                    <td className="pb-2 font-mono text-muted">
                      {a.mitre?.technique_id ?? ""} {a.mitre?.technique ?? ""}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="mt-6 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
            <div className="text-xs text-muted font-mono">
              Página {currentPage} de {totalPages} &bull; {realTotal} alerta
              {realTotal !== 1 ? "s" : ""}
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={() => goToPage(currentPage - 1)}
                disabled={currentPage === 1}
                className="px-3 py-1.5 text-xs rounded border border-surface/50 hover:bg-surface/50 disabled:opacity-50 disabled:pointer-events-none font-mono"
              >
                Anterior
              </button>

              {(() => {
                const btns: ReactNode[] = [];
                const show = 5;
                const half = Math.floor(show / 2);
                let start = Math.max(1, currentPage - half);
                let end = Math.min(totalPages, currentPage + half);
                if (start === 1) end = Math.min(totalPages, show);
                if (end === totalPages)
                  start = Math.max(1, totalPages - show + 1);

                if (start > 1) {
                  btns.push(
                    <button
                      key={1}
                      onClick={() => goToPage(1)}
                      className="px-3 py-1.5 text-xs rounded border border-surface hover:bg-surface/50 font-mono"
                    >
                      1
                    </button>,
                  );
                  btns.push(
                    <span
                      key="e"
                      className="px-2 py-1.5 text-xs text-muted font-mono"
                    >
                      …
                    </span>,
                  );
                }
                for (let i = start; i <= end; i++) {
                  btns.push(
                    <button
                      key={i}
                      onClick={() => goToPage(i)}
                      className={`px-3 py-1.5 text-xs rounded border font-mono ${i === currentPage ? "bg-crit text-white border-crit" : "border-surface hover:bg-surface/50 text-text"}`}
                    >
                      {i}
                    </button>,
                  );
                }
                if (end < totalPages) {
                  btns.push(
                    <span
                      key="e2"
                      className="px-2 py-1.5 text-xs text-muted font-mono"
                    >
                      …
                    </span>,
                  );
                  btns.push(
                    <button
                      key={totalPages}
                      onClick={() => goToPage(totalPages)}
                      className="px-3 py-1.5 text-xs rounded border border-surface hover:bg-surface/50 font-mono"
                    >
                      {totalPages}
                    </button>,
                  );
                }
                return <>{btns}</>;
              })()}

              <button
                onClick={() => goToPage(currentPage + 1)}
                disabled={currentPage === totalPages}
                className="px-3 py-1.5 text-xs rounded border border-surface/50 hover:bg-surface/50 disabled:opacity-50 disabled:pointer-events-none font-mono"
              >
                Siguiente
              </button>
            </div>
          </div>
        </>
      )}
    </LayoutShell>
  );
}
