from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import requests
import os
from dotenv import load_dotenv
import json

load_dotenv()

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

MOCK_TRIAJES = {}
if os.path.exists("resultados_ia_basico.json"):
    with open("resultados_ia_basico.json", "r", encoding="utf-8") as f:
        MOCK_TRIAJES = json.load(f)

TRAVIA_API_URL = os.getenv("TRAVIA_API_URL", "http://127.0.0.1:8000")

@app.get("/api/alerts")
def get_alerts():
    response = requests.get(f"{TRAVIA_API_URL}/alerts?status=new&limit=200", timeout=5)
    return response.json()

@app.get("/api/alerts/{alert_id}")
@app.post("/api/alerts/{alert_id}")
def triage_alert(alert_id: str):
    response = requests.get(f"{TRAVIA_API_URL}/alerts/{alert_id}")

    if response.status_code != 200:
        return {"status": "error", "message": "Alerta no encontrada"}
    
    alert_data = response.json()

    if alert_id in MOCK_TRIAJES:
        resultado_ia = MOCK_TRIAJES[alert_id]
    else:
        resultado_ia = {
                "veredicto": "true_positive" if "Credential" in alert_data.get("rule_name", "") else "false_positive",
                "confianza": "alta",
                "severidad_recalculada": alert_data.get("severity", "medium"),
                "resumen": f"Simulación de triaje Nivel 1 para la alerta {alert_id}.",
                "evidencias": [
                    f"Regla activada: {alert_data.get('rule_name', 'N/A')}",
                    f"Producto origen: {alert_data.get('source_product', 'SIEM')}",
                    f"Severidad detectada: {alert_data.get('severity', 'media')}"
                ],
                "accion_recomendada": "Revisar logs del usuario y validar si requiere contención."
            }


    # optional: enrquiecerr (consultar intel o usuarios)
    # src_ip = alert_data.get("src_ip")
    # intel_data = requests.get(f"{TRAVIA_API_URL}/intel/{src_ip}").json() if src_ip else {}

    #  Triaje IA 
    

    # resultado_ia = el_modulo_de_tu_compa.analizar_con_ia(alert_data)

    return {
        "status": "success",
        "alert_id": alert_id,
        "triaje": resultado_ia,
        "alerta_original": alert_data
    }