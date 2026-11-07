interface BarSeries {
  label: string;
  value: number;
  color?: string;
}

interface BarChartProps {
  series: BarSeries[];
  title: string;
  subtitle?: string;
  height?: number;
  className?: string;
}

export default function BarChart({
  series,
  title,
  subtitle,
  height = 180,
  className,
}: BarChartProps) {
  const max = Math.max(...series.map((s) => s.value));
  return (
    <div className={["flex flex-col gap-2", className].filter(Boolean).join(" ")}>
      <div className="flex items-center justify-between gap-2">
        <h3 className="text-xs font-semibold">{title}</h3>
        {subtitle && <p className="text-xs text-muted">{subtitle}</p>}
      </div>
      <div className="relative h-[calc(100%-2rem)] flex items-end gap-2 w-full">
        {series.map((s) => {
          const pct = (s.value / max) * 100;
          return (
            <div key={s.label} className="flex flex-col items-center gap-1.5 w-full">
              <div
                className="flex-1 bg-accent/10 rounded-t-sm transition-colors hover:bg-accent/20"
                style={{
                  height: `${Math.max(pct, 8)}%`,
                  backgroundColor: s.color,
                }}
              >
                <span className="hidden md:block absolute -top-6 left-1/2 -translate-x-1/2 text-[10px] text-muted font-mono">
                  {s.value}
                </span>
              </div>
              <span className="text-[10px] font-mono text-muted leading-none">{s.label}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}