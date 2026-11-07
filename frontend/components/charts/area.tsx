interface AreaChartProps {
  series: { label: string; value: number }[];
  title: string;
  subtitle?: string;
  height?: number;
  className?: string;
}

export default function AreaChart({
  series,
  title,
  subtitle,
  height = 160,
  className,
}: AreaChartProps) {
  const width = 360;
  const max = Math.max(...series.map((s) => s.value));
  const step = width / (series.length - 1);
  const points = series.map((s, i) => {
    const y = height - (s.value / max) * height;
    return `${i * step},${y}`;
  });

  return (
    <div className={["flex flex-col gap-2", className].filter(Boolean).join(" ")}>
      <div className="flex items-center justify-between gap-2">
        <h3 className="text-xs font-semibold">{title}</h3>
        {subtitle && <p className="text-xs text-muted">{subtitle}</p>}
      </div>
      <div className="relative w-full h-[calc(100%-2rem)]">
        <svg width={width} height={height} role="img" aria-label={title}>
          <polyline
            points={points.join(" ")}
            fill="none"
            stroke="#83b37a"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          {series.map((_, i) => (
            <circle
              key={i}
              cx={i * step}
              cy={height - (series[i].value / max) * height}
              r="2"
              fill="#83b37a"
            />
          ))}
        </svg>
        <div className="mt-2 flex justify-between text-[10px] font-mono text-muted">
          {series[0] && <span>{series[0].label}</span>}
          <span className="hidden md:inline">…</span>
          {series[series.length - 1] && <span>{series[series.length - 1].label}</span>}
        </div>
      </div>
    </div>
  );
}