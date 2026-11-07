from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import requests
import os
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

TRAVIA_API_URL = os.getenv("TRAVIA_API_URL")

@app.get("/api/alerts")
def get_alerts():
    response = requests.get(f"{TRAVIA_API_URL}/alerts?status=new&limit=200")
    return response.json()

@app.get("/api/alerts/{alert_id}")
def triage_alert(alert_id : str):
    response = requests.get("f{TRAVIA_API_URL}/alerts/{alert_id}")

    if (response.status_code != 200):
        return {"status": "error", "message" : "Alerta no encontrada"}
    
    alert_data = response.json()
    print("==================")
    print(alert_data)