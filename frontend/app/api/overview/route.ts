import { NextResponse } from "next/server";

/**
 * Ejemplo de ruta proxy hacia tu backend Python (FastAPI/Flask).
 *
 * Tu backend Python debe escuchar en http://localhost:8000 y exponer
 * este endpoint. Next.js reenvía la solicitud y devuelve la respuesta.
 */
export async function GET() {
  try {
    const res = await fetch("http://localhost:8000/api/overview", {
      headers: { "Content-Type": "application/json" },
      cache: "no-store",
    });

    if (!res.ok) {
      return NextResponse.json(
        { error: "Backend no disponible" },
        { status: 502 }
      );
    }

    const data = await res.json();
    return NextResponse.json(data);
  } catch {
    return NextResponse.json(
      { error: "No se pudo conectar con el backend Python" },
      { status: 502 }
    );
  }
}