"""Carga todo el dataset de Tarvia en una base DuckDB (tarvia.duckdb).

Uso:  python load_db.py --data ../DTT-UAB-The-Hack
Tarda ~1 min. Se ejecuta una vez; luego todo el sistema consulta la base.
"""
import argparse, glob, os, time, duckdb

DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tarvia.duckdb")


REQUIRED = ["03_alertas/alertas.jsonl", "04_logs", "02_inventario/activos.csv",
            "05_inteligencia/geoip_asn.csv", "05_inteligencia/ti_feed.jsonl", "01_contexto/catalogo_casos_de_uso.csv"]


def find_data_dir(path: str) -> str:
    """Acepta la carpeta del reto o cualquier carpeta que la contenga (p. ej. zip descomprimido dos veces)."""
    path = os.path.abspath(path)
    for root, dirs, _ in os.walk(path):
        if "03_alertas" in dirs and "04_logs" in dirs:
            return root
        if root.count(os.sep) - path.count(os.sep) >= 3:
            dirs.clear()
    raise SystemExit(f"\nNo encuentro los datos del reto dentro de:\n  {path}\n"
                     "Indica con --data la carpeta que contiene 01_contexto, 03_alertas, 04_logs, 05_inteligencia...")


def check(data_dir: str):
    missing = [r for r in REQUIRED if not os.path.exists(os.path.join(data_dir, *r.split("/")))]
    small = [f for f in glob.glob(os.path.join(data_dir, "04_logs", "*")) if os.path.getsize(f) < 1000]
    if missing:
        raise SystemExit("\nFaltan archivos del reto en " + data_dir + ":\n  " + "\n  ".join(missing))
    if small:
        raise SystemExit("\nEstos logs pesan menos de 1 KB (¿descarga incompleta o punteros de Git LFS?):\n  "
                         + "\n  ".join(small))


def load(data_dir: str, db_path: str = DB):
    data_dir = find_data_dir(data_dir)
    check(data_dir)
    print(f"Datos del reto: {data_dir}")
    data_dir = data_dir.replace("\\", "/")      # DuckDB en Windows prefiere barras normales
    if os.path.exists(db_path):
        os.remove(db_path)
    con = duckdb.connect(db_path)
    t0 = time.time()

    def jsonl(table, path):
        # union_by_name + sample_size=-1: los JSON tienen campos que varían entre eventos
        con.execute(f"""CREATE TABLE {table} AS SELECT * FROM read_json('{path}',
            format='newline_delimited', union_by_name=true, sample_size=-1)""")

    def csv(table, path):
        con.execute(f"CREATE TABLE {table} AS SELECT * FROM read_csv('{path}', header=true, all_varchar=true)")

    # Logs: el nombre de la tabla es el de la fuente (proxy, dns, edr_events...)
    for path in sorted(glob.glob(os.path.join(data_dir, "04_logs", "*"))):
        name, ext = os.path.splitext(os.path.basename(path))
        (jsonl if ext == ".jsonl" else csv)(name, path)
        # timestamp como texto ISO para comparar igual en todas las fuentes
        cols = [r[0] for r in con.execute(f"DESCRIBE {name}").fetchall()]
        if "timestamp" in cols:
            con.execute(f"ALTER TABLE {name} ALTER timestamp TYPE VARCHAR")
            con.execute(f"ALTER TABLE {name} ADD COLUMN ts TIMESTAMP")
            con.execute(f"UPDATE {name} SET ts = CAST(replace(replace(timestamp,'T',' '),'Z','') AS TIMESTAMP)")

    for path in glob.glob(os.path.join(data_dir, "02_inventario", "*.csv")):
        csv(os.path.splitext(os.path.basename(path))[0], path)

    csv("geoip", os.path.join(data_dir, "05_inteligencia", "geoip_asn.csv"))
    jsonl("ti_feed", os.path.join(data_dir, "05_inteligencia", "ti_feed.jsonl"))
    jsonl("sandbox", os.path.join(data_dir, "05_inteligencia", "sandbox_informes.jsonl"))
    csv("casos_de_uso", os.path.join(data_dir, "01_contexto", "catalogo_casos_de_uso.csv"))

    # Alertas: columnas principales + el JSON completo en `raw`
    con.execute(f"""CREATE TABLE alerts AS
        SELECT j->>'alert_id' AS alert_id,
               CAST(replace(replace(j->>'created_at','T',' '),'Z','') AS TIMESTAMP) AS ts,
               j->>'source_product' AS source_product, j->>'rule_id' AS rule_id,
               j->>'rule_name' AS rule_name, j->>'severity' AS rule_severity,
               j->>'runbook' AS runbook, CAST(j AS VARCHAR) AS raw
        FROM (SELECT json AS j FROM read_ndjson_objects('{os.path.join(data_dir, '03_alertas', 'alertas.jsonl')}'))""")
    con.execute(f"""CREATE TABLE alerts_dev AS SELECT json->>'alert_id' AS alert_id
        FROM read_ndjson_objects('{os.path.join(data_dir, '03_alertas', 'alertas_muestra_desarrollo.jsonl')}')""")

    tables = [r[0] for r in con.execute("SHOW TABLES").fetchall()]
    for t in tables:
        n = con.execute(f"SELECT count(*) FROM {t}").fetchone()[0]
        print(f"  {t:24s} {n:>8,}")
    print(f"Cargado en {time.time() - t0:.0f}s -> {db_path}")
    con.close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True, help="Carpeta del repo del reto")
    load(ap.parse_args().data)
