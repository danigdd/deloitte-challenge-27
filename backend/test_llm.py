"""Diagnóstico rápido de la conexión con el LLM (API compatible con OpenAI).

Uso (PowerShell), con las variables ya puestas:
    $env:OPENAI_API_KEY="..."; $env:OPENAI_BASE_URL="https://dcc-llm-gw.uab.cat/uabthehack/v1"; $env:TRIAGE_MODEL="ornith"
    python test_llm.py

Comprueba 4 cosas y dice cuál falla: conexión, modelo, chat simple y llamadas a herramientas.
"""
import json, os, sys, time

import openai

KEY, URL, MODEL = os.getenv("OPENAI_API_KEY"), os.getenv("OPENAI_BASE_URL"), os.getenv("TRIAGE_MODEL")
if not (KEY and URL and MODEL):
    sys.exit("Faltan variables: OPENAI_API_KEY, OPENAI_BASE_URL y TRIAGE_MODEL")
c = openai.OpenAI(timeout=120)

print(f"1) Conexión con {URL} ...", end=" ", flush=True)
try:
    models = [m.id for m in c.models.list()]
    print("OK. Modelos:", ", ".join(models))
    if MODEL not in models:
        print(f"   ⚠ '{MODEL}' no está en la lista: revisa TRIAGE_MODEL")
except Exception as e:
    print(f"FALLA ({type(e).__name__}): {e}")
    print("   Si no es un error de clave (401), el servidor puede no tener /models; sigo igualmente.")

print("2) Chat simple ...", end=" ", flush=True)
t = time.time()
r = c.chat.completions.create(model=MODEL, messages=[{"role": "user", "content": "Responde solo: OK"}], temperature=0)
print(f"OK en {time.time() - t:.1f}s → {r.choices[0].message.content!r}")

tool = [{"type": "function", "function": {"name": "intel", "description": "Reputación de un indicador",
         "parameters": {"type": "object", "properties": {"indicator": {"type": "string"}}, "required": ["indicator"]}}}]
msgs = [{"role": "user", "content": "Consulta la reputación del dominio aplihartom.com usando la herramienta."}]
for choice in ("required", "auto"):
    print(f"3) Herramientas con tool_choice={choice} ...", end=" ", flush=True)
    try:
        r = c.chat.completions.create(model=MODEL, messages=msgs, tools=tool, tool_choice=choice, temperature=0)
        m = r.choices[0].message
        if m.tool_calls:
            print("OK, llamadas nativas:", m.tool_calls[0].function.name, m.tool_calls[0].function.arguments)
            print(f"   → usa: $env:TRIAGE_TOOL_CHOICE=\"{choice}\"")
            break
        print("sin tool_calls nativos; texto:", (m.content or "")[:150])
    except Exception as e:
        print(f"no soportado ({type(e).__name__}): {str(e)[:150]}")
else:
    print("   El modelo no usa herramientas nativas: el agente las leerá del texto (más frágil, pero funciona).")

print("4) Contexto largo (system prompt real del agente) ...", end=" ", flush=True)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import prompts
t = time.time()
try:
    r = c.chat.completions.create(model=MODEL, temperature=0, messages=[
        {"role": "system", "content": prompts.system_prompt("RB-02")},
        {"role": "user", "content": "Di en una frase cuál es tu rol."}])
    u = r.usage
    print(f"OK en {time.time() - t:.1f}s · {u.prompt_tokens if u else '?'} tokens de entrada → {r.choices[0].message.content[:120]!r}")
except Exception as e:
    print(f"FALLA ({type(e).__name__}): {str(e)[:200]}")
    print("   Probablemente el contexto del modelo es pequeño: avisa para recortar el system prompt.")
