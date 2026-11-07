from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import requests
import os
from dotenv import load_dotenv
from context import Ctx

from respuesta_ia import triar_alerta, resultado_guardado

load_dotenv()

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

TRAVIA_API_URL = os.getenv("TRAVIA_API_URL", "http://127.0.0.1:8000")

@app.get("/api/alerts")
def get_alerts():
    response = requests.get(f"{TRAVIA_API_URL}/alerts?status=new&limit=20000", timeout=5)
    return response.json()

@app.get("/api/alerts/{alert_id}")
@app.post("/api/alerts/{alert_id}")
def triage_alert(alert_id: str):
    #instant
    resultado = resultado_guardado(alert_id)
    if resultado:
        # Aquí cargamos la alerta original de la BD para que el frontend no dé 404
        ctx = Ctx()
        alert_data = ctx.get_alert(alert_id)
        return {
            "status": "success",
            "alert_id": alert_id,
            "triaje": resultado,
            "alerta_original": alert_data
        }

    # Si no hay resultado, llamamos a la API y calculamos
    response = requests.get(f"{TRAVIA_API_URL}/alerts/{alert_id}", timeout=5)
    if response.status_code != 200:
        return {"status": "error", "message": "Alerta no encontrada"}
    
    alert_data = response.json()
    resultado_ia = triar_alerta(alert_data)

    return {
        "status": "success",
        "alert_id": alert_id,
        "triaje": resultado_ia,
        "alerta_original": alert_data
    }