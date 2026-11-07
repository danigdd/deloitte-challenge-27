@app.get("/api/alerts")
def get_alerts():
    """Alertas recientes detectadas por el agente."""
    return {"total": 0, "items": []}


@app.post("/api/agent/ask", response_model=AskResponse)
def ask_agent(req: AskRequest):
    """
    Envía una consulta al agente SOC.
    Aquí es donde conectarías tu lógica de IA (LLM, reglas, correlación, etc.).
    """
    return AskResponse(
        response="El agente aún no está conectado. Implementa tu lógica de IA aquí.",
        findings=[],
    )