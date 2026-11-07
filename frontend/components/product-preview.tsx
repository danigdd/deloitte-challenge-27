export default function ProductPreview() {
  return (
    <div className="border border-surface rounded-sm overflow-hidden flex flex-col h-full">
      <div className="bg-surface border-b border-surface px-4 py-2 flex items-center justify-between">
        <div className="flex items-center gap-1.5">
          <span className="h-1.5 w-1.5 rounded-full bg-crit/60"></span>
          <span className="h-1.5 w-1.5 rounded-full bg-warn/60"></span>
          <span className="h-1.5 w-1.5 rounded-full bg-accent/60"></span>
        </div>
        <div className="text-[10px] font-mono text-muted tracking-wider">
          soc.local — dashboard
        </div>
      </div>
      <div className="p-4 grid grid-cols-2 gap-3 min-h-[320px]">
        <div className="col-span-2 border border-surface rounded-sm p-3 bg-surface flex flex-col justify-center items-center text-center">
          <p className="text-xs text-muted">Eventos (24h)</p>
          <p className="text-sm font-mono font-semibold text-text">—</p>
        </div>
        <div className="col-span-2 border border-surface rounded-sm p-3 bg-surface flex flex-col justify-center items-center text-center">
          <p className="text-xs text-muted">Alertas abiertas</p>
          <p className="text-sm font-mono font-semibold text-text">—</p>
        </div>
        <div className="border border-surface rounded-sm p-3 bg-surface flex flex-col justify-center items-center text-center">
          <p className="text-xs text-muted">Críticas</p>
          <p className="text-sm font-mono font-semibold text-text">—</p>
        </div>
        <div className="border border-surface rounded-sm p-3 bg-surface flex flex-col justify-center items-center text-center">
          <p className="text-xs text-muted">MTTR</p>
          <p className="text-sm font-mono font-semibold text-text">—</p>
        </div>
      </div>
      <div className="bg-surface border-t border-surface p-3 flex items-center gap-3 justify-center">
        <span className="flex h-1 w-1 items-center">
          <span className="h-1 w-1 rounded-full bg-accent"></span>
        </span>
        <p className="text-[10px] font-mono text-muted">
          Esperando conexión con el agente…
        </p>
      </div>
    </div>
  );
}