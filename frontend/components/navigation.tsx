import Link from "next/link";

const navLinks = [
  { href: "/", label: "Product" },
  { href: "/dashboard", label: "Dashboard" },
  { href: "/alerts", label: "Alertas" },
  { href: "/investigation", label: "Investigación" },
  { href: "/reports", label: "Informes" },
];

export default function Navigation() {
  return (
    <nav className="fixed top-0 left-0 right-0 z-40 border-b border-surface">
      <div className="flex h-12 items-center justify-between px-4">
        <Link
          href="/"
          className="flex items-center gap-2 font-mono text-xs font-semibold tracking-wider text-accent focus-visible-ring"
        >
          <span className="relative inline-block h-[0.85em] w-auto after:absolute after:inset-0 after:bg-accent after:-skew-y-12 after:opacity-30 after:-z-10 after:rounded-sm">
            SOC
          </span>
          <span className="text-text">Analyst</span>
        </Link>

        <div className="hidden md:flex items-center gap-5 text-sm text-muted">
          {navLinks.map((link) => (
            <Link
              key={link.href}
              href={link.href}
              className="text-text hover:text-accent focus-visible-ring"
            >
              {link.label}
            </Link>
          ))}
        </div>

        <div className="flex items-center gap-3">
          <span className="flex h-2 w-2 items-center">
            <span className="h-2 w-2 rounded-full bg-accent"></span>
          </span>
          <span className="text-xs font-mono text-muted">API conectada</span>
        </div>
      </div>
    </nav>
  );
}