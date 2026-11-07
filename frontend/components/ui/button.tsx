import * as React from "react";

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "default" | "ghost" | "outline";
  asChild?: boolean;
}

export function Button({
  className,
  variant = "default",
  asChild = false,
  ...props
}: ButtonProps) {
  const Comp = asChild ? React.Fragment : "button";
  const base =
    "inline-flex items-center justify-center gap-2 rounded-sm border border-transparent font-medium text-sm transition-colors focus-visible-ring disabled:opacity-50 disabled:pointer-events-none";
  const variants: Record<string, string> = {
    default: "bg-accent text-bg hover:bg-accent-hover",
    ghost: "text-text hover:bg-surface-2",
    outline: "border-surface text-text hover:border-accent hover:text-accent",
  };
  return (
    <Comp
      className={[base, variants[variant], className].filter(Boolean).join(" ")}
      {...props}
    />
  );
}