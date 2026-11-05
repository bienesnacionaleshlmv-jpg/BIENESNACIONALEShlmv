"""Inicia NEXUS localmente con la configuración privada .env (no se publica en GitHub)."""
import os, subprocess, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
ENV=ROOT/'.env'
if not ENV.is_file():
    raise SystemExit('Falta .env. Copia .env.ejemplo como .env y configura tu dominio y clave.')
for raw in ENV.read_text(encoding='utf-8-sig').splitlines():
    raw=raw.strip()
    if not raw or raw.startswith('#'):continue
    key,sep,val=raw.partition('=')
    if not sep or not key.strip():continue
    os.environ[key.strip()]=val.strip().strip('"').strip("'")
os.environ.setdefault('HLMV_DATOS',str(ROOT/'datos'))
print('Servidor en http://127.0.0.1:8895 (solo PC local).')
print('Usa la dirección HTTPS fija por Cloudflare Tunnel para celulares y etiquetas QR.')
subprocess.run([sys.executable,'-u',str(ROOT/'app'/'server.py'),'--no-browser','--port','8895'],cwd=ROOT,check=True)
