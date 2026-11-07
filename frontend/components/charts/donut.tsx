interface DonutSegment {
  label: string;
  value: number;
  color: string;
}

interface DonutProps {
  segments: DonutSegment[];
  totalLabel: string;
  totalValue: string;
  size?: number;
  className?: string;
}

function polarToCartesian(centerX: number, centerY: number, radius: number, angleInDegrees: number) {
  const angleInRadians = ((angleInDegrees - 90) * Math.PI) / 180;
  return {
    x: centerX + radius * Math.cos(angleInRadians),
    y: centerY + radius * Math.sin(angleInRadians),
  };
}

function describeArc(x: number, y: number, radius: number, startAngle: number, endAngle: number) {
  const start = polarToCartesian(x, y, radius, endAngle);
  const end = polarToCartesian(x, y, radius, startAngle);
  const largeArcFlag = endAngle - startAngle <= 180 ? "0" : "1";
  const d = [
    "M",
    start.x,
    start.y,
    "A",
    radius,
    radius,
    0,
    largeArcFlag,
    0,
    end.x,
    end.y,
  ].join(" ");
  return d;
}

export default function DonutChart({
  segments,
  totalLabel,
  totalValue,
  size = 210,
  className,
}: DonutProps) {
  const total = segments.reduce((sum, s) => sum + s.value, 0);
  const radius = size / 2 - 24;
  const cx = size / 2;
  const cy = size / 2;
  let startAngle = 0;

  const arcs = segments.map((segment) => {
    const sweepAngle = (segment.value / total) * 360;
    const arc = describeArc(cx, cy, radius, startAngle, startAngle + sweepAngle);
    startAngle += sweepAngle;
    return <path key={segment.label} d={arc} fill="none" stroke={segment.color} strokeWidth="10" strokeLinecap="round" />;
  });

  return (
    <div className={["flex flex-col items-center gap-2", className].filter(Boolean).join(" ")}>
      <svg role="img" aria-label={totalLabel} width={size} height={size}>
        <path d={describeArc(cx, cy, radius, 0, 360)} fill="none" stroke="#1c2029" strokeWidth="10" strokeLinecap="round" />
        {arcs}
      </svg>
      <div className="text-center">
        <p className="text-xs font-mono font-semibold text-text">{totalValue}</p>
        <p className="text-xs text-muted">{totalLabel}</p>
      </div>
    </div>
  );
}