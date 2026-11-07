import Link from "next/link";

interface ShellItem {
  href: string;
  label: string;
}

const shellItems: ShellItem[] = [
  { href: "/dashboard", label: "Overview" },
  { href: "/alerts", label: "Alerts" },
  { href: "/investigation", label: "Incidents" },
  { href: "/dashboard#agent", label: "Agent activity" },
  { href: "/reports", label: "Reports" },
];

interface LayoutShellProps {
  children: React.ReactNode;
  title: string;
  description?: string;
}

export default function LayoutShell({
  children,
  title,
  description,
}: LayoutShellProps) {
  return (
    <div className="flex h-[calc(100vh-3rem)]">
      <aside className="hidden lg:flex lg:w-60 flex-col border-r border-surface px-5 py-6">
        <div className="mb-10">
          <span className="font-mono text-xs font-semibold tracking-wider text-accent">
            SOC
          </span>
          <span className="text-sm font-medium text-text">Analyst</span>
        </div>
        <nav className="space-y-1.5 text-sm">
          {shellItems.map((item) => (
            <Link
              key={item.href}
              href={item.href}
              className="flex items-center gap-2.5 px-3 py-2 rounded-sm text-muted hover:text-text hover:bg-surface-2 focus-visible-ring"
            >
              <span className="w-3 h-3 rounded-sm border border-transparent bg-current/10"></span>
              {item.label}
            </Link>
          ))}
        </nav>
      </aside>

      <section className="flex-1 min-w-0 overflow-y-auto bg-surface-2 p-6 md:p-8">
        <header className="flex flex-col md:flex-row md:items-center justify-between gap-3 mb-8">
          <div>
            <h1 className="text-lg font-semibold tracking-tight">{title}</h1>
            {description && (
              <p className="text-xs text-muted mt-1">{description}</p>
            )}
          </div>
          <div className="flex items-center gap-3">
            <span className="flex h-2 w-2 items-center">
              <span className="h-2 w-2 rounded-full bg-accent"></span>
            </span>
            <span className="text-xs font-mono text-muted">Sistema listo</span>
          </div>
        </header>
        <div className="max-w-[90rem]">{children}</div>
      </section>
    </div>
  );
}