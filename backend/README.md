# Tarvia · Triaje N1 con IA

Sistema de triaje de nivel 1 para el reto de Deloitte en UAB The Hack. Dos capas:

1. **Prefiltro determinista** (`prefilter.py`): cierra el ruido que la política permite cerrar, siempre
   verificándolo contra los logs y citando la regla, el cambio aprobado o el runbook en que se basa.
2. **Agente LLM con herramientas** (`agent.py`): investiga el resto como un analista N1, consultando
   logs, CMDB, directorio, RRHH, TIP y sandbox. El código, no el modelo, aplica la matriz de severidad,
   los criterios de escalado y quién aprueba cada acción.

Todo queda en `triage.db` (SQLite), que es lo único que lee el dashboard.

```
alertas.jsonl ─► prefiltro ─┬─► auto_close   (10.705 · 96,8 %)  ticket con la regla que lo justifica
                            ├─► human_batch  (61 · 0,6 %)       medium: el analista confirma en lote
                            └─► agent        (295 · 2,7 %)      ─► 179 investigaciones agrupadas
                                                                    ─► LLM + herramientas
                                                                    ─► matriz y escalado en código
                                                                    ─► ticket_salida.schema.json
```

## Puesta en marcha

```bash
pip install -r requirements.txt
python load_db.py --data ../DTT-UAB-The-Hack        # crea tarvia.duckdb (~10 s)
python run_prefilter.py                             # prefiltro sobre las 11.061 alertas (~50 s)

export ANTHROPIC_API_KEY=...                        # o: export TRIAGE_PROVIDER=openai OPENAI_API_KEY=...
python agent.py --alert ALR-20261009-011791         # una alerta
python agent.py --queue --limit 10                  # la cola del agente
python eval/run_eval.py                             # medir acierto contra casos con veredicto esperado
```

### Con Claude Code y una suscripción Pro/Max (sin clave de API)

```powershell
# una vez: instalar Claude Code e iniciar sesión con la cuenta Pro
claude            # abre la sesión; luego /exit
# en la terminal donde lancéis el agente, sin ANTHROPIC_API_KEY definida:
python agent.py --alert ALR-20261009-011791 --provider claude_code
python eval/run_eval.py --provider claude_code
```

Para no escribir `--provider` cada vez: `$env:TRIAGE_PROVIDER="claude_code"` (PowerShell).

Cómo funciona: por cada investigación se lanza `claude -p` con nuestro system prompt. Claude Code hace el
bucle de consultas por dentro, pero **solo puede ejecutar `python tools_cli.py ...`** (`--tools Bash` +
`--allowedTools "Bash(python tools_cli.py:*)"`): no puede leer ni escribir ficheros, ni navegar, ni lanzar otros
comandos; lo que intente fuera de esa lista se bloquea y queda en la traza. Las herramientas son de solo lectura y
devuelven los datos como `<datos_no_confiables>`. La respuesta final se pasa por `finalize()`, igual que con la API.

Notas: el cupo de uso es el de la suscripción (sobra para los 20 casos de evaluación y las 10 alertas de la
defensa; para las 179 investigaciones de la cola, repartid entre cuentas o en varios días). En Windows, Claude Code
necesita Git for Windows para su terminal. Si vuestro Python se llama distinto, `$env:TRIAGE_PY="py"`.

Sin clave de API: `--provider mock` recorre todo el circuito (herramientas, política, base de datos)
con un LLM simulado que contesta `needs_more_info`. Sirve para desarrollar el dashboard.

Modelo: `TRIAGE_MODEL` (por defecto `claude-sonnet-5-5` con Anthropic, `gpt-4o-mini` con OpenAI).
Para un modelo local con Ollama: `TRIAGE_PROVIDER=openai OPENAI_BASE_URL=http://localhost:11434/v1 OPENAI_API_KEY=x TRIAGE_MODEL=qwen2.5:14b`.

## Archivos

| Archivo | Qué hace |
|---|---|
| `load_db.py` | Carga logs, inventario, inteligencia y alertas en DuckDB |
| `policy.py` | Matriz de severidad, ajustes ±1, SLA, reglas internas de Tarvia, detector de texto manipulador |
| `context.py` | Consultas a la base. Son las herramientas del agente; cada llamada se registra en una `Trace` |
| `prefilter.py` | Reglas de cierre por caso de uso + correlación ±24 h que reabre cierres sospechosos |
| `run_prefilter.py` | Ejecuta el prefiltro, agrupa en tickets y escribe `triage.db` |
| `prompts.py` | System prompt (política + empresa + runbook de la alerta) y user prompt |
| `agent.py` | Bucle tool-use (Claude Code, Anthropic, OpenAI-compatible o mock) y `finalize()`, que aplica la política |
| `tools_cli.py` | Las herramientas del agente como comando (lo único que Claude Code puede ejecutar) |
| `store.py` | Esquema de `triage.db`: el contrato con el dashboard |
| `eval/` | 20 casos reales con veredicto esperado y el script que mide el acierto |
| `knowledge/` | Copia de la política, la ficha de empresa, los runbooks y los esquemas del reto |

## Contrato con el dashboard (`triage.db`)

| Tabla | Contenido |
|---|---|
| `prefilter` | Una fila por alerta: `disposition` (auto_close / human_batch / agent), veredicto, severidad, `basis` (en qué se basa), `route_reason` (por qué va al agente), `injection`, `trace` (JSON de comprobaciones ✓/✗) |
| `tickets` | Una fila por ticket. `ticket_json` sigue `ticket_salida.schema.json`. `trace` es la lista de pasos (consultas, razonamiento, política). `origin` = prefilter / agent / eval. `status` = closed / pending_review / pending_batch_review |
| `ticket_alerts` | Qué alertas agrupa cada ticket |
| `human_actions` | Lo que hace el analista en el dashboard (aprobar, corregir veredicto, escalar). Tabla vacía para que la rellene el frontend |

Cada paso de `trace` tiene `kind`: `read` (leer alerta), `query` (herramienta), `check` (condición de
política, con `passed`), `thought` (razonamiento del modelo), `policy` (matriz, escalado, OT). Con eso el
dashboard puede pintar «qué consultó, en qué se basó y qué decidió el código».

Para aprobaciones de contención: `POST /approvals` y `POST /containment/{accion}` de la API simulada del reto
(`06_herramientas/mock_soc_api.py`); el botón de aprobar del dashboard debe llamar ahí.

## Decisiones de diseño (para la defensa)

- **El prefiltro verifica, no confía en el texto de la alerta.** Ejemplos: una campaña de correo solo se
  cierra si `email_clicks` no tiene clics de riesgo; el bucket público por Terraform solo se cierra si la
  identidad `svc_ecom_deploy` no aparece usada desde fuera de AWS (y sí aparece, desde una IP con UA de
  Kali: por eso esas 50 alertas van al agente).
- **Correlación ±24 h**: una alerta «de ruido» que comparte equipo, usuario, IP o dominio con algo que se
  está investigando se reabre (12 casos).
- **Texto del atacante**: el prefiltro nunca cierra una alerta cuyos datos contienen instrucciones dirigidas
  a sistemas automáticos (13 alertas, una campaña de phishing). El agente recibe todos los datos entre
  `<datos_no_confiables>` y debe reportar esas instrucciones como evidencia.
- **Severidad por código**: el modelo aporta hechos (`severity_factors`) y `policy.final_severity` aplica la
  matriz. Mismo caso → misma severidad, y el `severity_rationale` explica el cálculo.
- **La IA propone, la persona decide**: `requires_approval` sale de la tabla del §4 de la política, no del
  modelo. Las acciones sobre OT se descartan siempre.
- **Evidencia verificable**: si el modelo cita un `event_id` que no vio en ninguna respuesta de herramienta,
  el ticket lo marca como no verificado.

## Limitaciones conocidas (sed honestos con ellas)

- Las reglas del prefiltro están ajustadas a los patrones de **este** dataset (dominios de CDN, SAP, SCCM,
  servicios de reputación de AV). En un SOC real habría que mantenerlas como cualquier lista de exclusión.
- La criticidad de identidades (VIP/privilegiada → Alta; servicio privilegiada → Crítica) es un supuesto
  nuestro: la política no la define.
- La matriz manda 73 intentos pequeños de credential stuffing (1 IP, 0 éxitos, rate limit activo) a `high`
  porque la tienda es crítica (high × Crítica = critical, −1 por bloqueo). Lo dejamos así por fidelidad a
  la política y lo señalamos como posible ajuste de la regla.
- La ventana de SCCM se comprueba con 1 h de tolerancia por la ambigüedad de zona horaria del cambio.
- Agrupación del prefiltro por patrón (IP, remitente, día...), no por incidente real. La agrupación por
  incidente (nivel 2-3) está apuntada en el agente con `related_incidents`, pero no se consolida aún.
- **El agente no se ha evaluado todavía con un LLM real** (en el entorno de desarrollo no había clave de
  API). Los 7 casos de control que cierra el prefiltro aciertan; los 13 que van al agente hay que medirlos
  con `python eval/run_eval.py`.
