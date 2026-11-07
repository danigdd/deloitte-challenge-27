from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import requests

app = FastAPI()

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

TRAVIA_API_URL = "http://127.0.0.1:8000"

@app.get("/api/alerts")
def get_alerts():
    response = requests.get(f"{TRAVIA_API_URL}/alerts?status=new&limit=10")
    return response.json()