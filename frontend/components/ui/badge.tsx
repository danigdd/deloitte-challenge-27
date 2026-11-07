interface BadgeProps {
  className?: string;
  children?: React.ReactNode;
  variant?: "default" | "demo";
}

export function Badge({
  className,
  children,
  variant = "default",
  ...props
}: BadgeProps) {
  const base =
    "inline-flex items-center gap-1 rounded-sm border px-2 py-0.5 text-xs font-mono font-medium transition-colors";
  const variants: Record<string, string> = {
    default: "border-surface text-muted hover:border-surface/60",
    demo: "border-accent text-accent",
  };
  return (
    <span
      className={[base, variants[variant], className].filter(Boolean).join(" ")}
      {...props}
    >
      {children}
    </span>
  );
}