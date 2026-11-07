"use client";

export default function BackButton() {
  return (
    <button
      onClick={() => window.history.back()}
      className="text-xs font-mono text-muted hover:text-text underline underline-offset-4"
    >
      ← Volver a alertas
    </button>
  );
}
