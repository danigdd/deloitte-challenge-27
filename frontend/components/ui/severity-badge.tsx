type Severity = "low" | "medium" | "high" | "critical";

const SEVERITY: Record<
  Severity,
  { label: string; color: string; muted: string }
> = {
  low: { label: "Low", color: "text-accent", muted: "bg-accent-muted" },
  medium: { label: "Medium", color: "text-warn", muted: "bg-warn-muted" },
  high: { label: "High", color: "text-warn", muted: "bg-warn-muted" },
  critical: { label: "Critical", color: "text-crit", muted: "bg-crit-muted" },
};

interface SeverityBadgeProps {
  severity: Severity;
  className?: string;
}

export function SeverityBadge({
  severity,
  className,
}: SeverityBadgeProps) {
  const s = SEVERITY[severity];
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-sm border border-transparent px-2 py-0.5 text-xs font-mono font-medium ${s.muted} ${s.color} ${className ?? ""}`}
    >
      <span className="inline-block w-1.5 h-1.5 rounded-full bg-current"></span>
      {s.label}
    </span>
  );
}