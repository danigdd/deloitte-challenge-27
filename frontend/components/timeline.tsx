import { SeverityBadge } from "@/components/ui/severity-badge";

type Severity = "low" | "medium" | "high" | "critical";

interface TimelineEvent {
  time: string;
  title: string;
  source: string;
  severity: Severity;
  description?: string;
}

interface TimelineProps {
  events: TimelineEvent[];
  className?: string;
}

export default function Timeline({ events, className }: TimelineProps) {
  return (
    <div className={["border border-surface rounded-sm overflow-hidden", className].filter(Boolean).join(" ")}>
      <table className="w-full text-xs border-collapse">
        <thead>
          <tr>
            <th className="w-16 pb-3 pt-4 text-left font-mono text-muted font-medium">Time</th>
            <th className="pb-3 pt-4 text-left font-mono text-muted font-medium">Source</th>
            <th className="pb-3 pt-4 text-left font-mono text-muted font-medium">Severity</th>
            <th className="pb-3 pt-4 text-left font-mono text-muted font-medium">Event</th>
          </tr>
        </thead>
        <tbody>
          {events.map((event, i) => (
            <tr key={event.time} className="border-t border-surface/50 group">
              <td className="pb-2 pt-3 font-mono text-text">{event.time}</td>
              <td className="pb-2 pt-3 font-mono text-muted">{event.source}</td>
              <td className="pb-2 pt-3">
                <SeverityBadge severity={event.severity} />
              </td>
              <td className="pb-2 pt-3 text-text">{event.title}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}