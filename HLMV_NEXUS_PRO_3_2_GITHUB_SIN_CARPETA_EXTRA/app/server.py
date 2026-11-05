"""Inventario HLMV — servidor local, SQLite, QR, documentos y copias de seguridad.
Python 3.10+, sin servicios en la nube ni dependencias instalables.
"""
import argparse
import base64
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import sqlite3
import sys
import threading
import time
import uuid
import unicodedata
import webbrowser
import zipfile
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, unquote, urlsplit
from xml.sax.saxutils import escape as xml_escape
import zlib
import struct

BASE = Path(__file__).resolve().parent
ROOT = BASE.parent
sys.path.insert(0, str(ROOT / 'vendor'))
import qrcode
from excel_importer import parse_workbook, norm as excel_norm
from pdf_siafi_importer import parse_siafi_pdf, PDFImportError, norm as pdf_norm
from central_auth import CentralAuth, SESSION_SECONDS, password_ok, password_hash, USER_PATTERN, utc_now

DATA = Path(os.environ.get('HLMV_DATOS', str(ROOT / 'datos'))).resolve()
MEDIA = DATA / 'imagenes'
DB_PATH = DATA / 'inventario.sqlite3'
VALID_COL = {'hospital', 'areas', 'empleados', 'bienes', 'personas'}
MAX_BODY = 30 * 1024 * 1024
LOCK = threading.RLock()
SESSIONS = {} # Compatibilidad con respaldos antiguos; sesiones nuevas usan la tabla sessions.
AUTH = None
LAN_MODE = False
# Seguridad: intentos fallidos de acceso y expiración de sesiones.
FAILED_LOGINS = {}
SESSION_TTL = 12 * 3600
LOGIN_WINDOW = 15 * 60
LOGIN_MAX_FAILURES = 8


def db_connect():
    c = sqlite3.connect(str(DB_PATH), timeout=20)
    c.row_factory = sqlite3.Row
    c.execute('PRAGMA busy_timeout=20000')
    return c


def init_db():
    # En un despliegue público es obligatorio fijar el enlace HTTPS antes de
    # imprimir etiquetas QR; nunca asumir la dirección recibida por Host.
    if os.environ.get('HLMV_CLOUD_MODE')=='1':
        url=os.environ.get('HLMV_PUBLIC_URL','').strip()
        parsed=urlsplit(url)
        if (parsed.scheme!='https' or not parsed.netloc or parsed.path not in ('','/') or parsed.query or parsed.fragment
                or not parsed.hostname or parsed.hostname in ('localhost','127.0.0.1')
                or 'tudominio' in parsed.hostname or 'ejemplo' in parsed.hostname
                or parsed.hostname.endswith('.trycloudflare.com')):
            raise RuntimeError('Configura HLMV_PUBLIC_URL con TU dominio HTTPS fijo y real (no ejemplos ni túneles temporales).')
    # Evitar pérdida silenciosa de datos si Railway no tiene volumen persistente.
    if os.environ.get('RAILWAY_SERVICE_ID') and os.environ.get('RAILWAY_VOLUME_MOUNT_PATH') != '/data':
        raise RuntimeError('Falta conectar un volumen persistente de Railway con ruta /data. No se iniciará el inventario sin ese respaldo.')
    DATA.mkdir(parents=True, exist_ok=True)
    MEDIA.mkdir(parents=True, exist_ok=True)
    with db_connect() as c:
        c.execute('CREATE TABLE IF NOT EXISTS docs (collection TEXT NOT NULL, id TEXT NOT NULL, data TEXT NOT NULL, updated TEXT NOT NULL, PRIMARY KEY(collection,id))')
        c.execute('CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
        c.execute('CREATE TABLE IF NOT EXISTS audit (seq INTEGER PRIMARY KEY AUTOINCREMENT, date TEXT NOT NULL, action TEXT NOT NULL, collection TEXT, document_id TEXT, details TEXT)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_docs_col ON docs(collection)')
        c.execute('CREATE TABLE IF NOT EXISTS import_reviews (id TEXT PRIMARY KEY, created TEXT NOT NULL, file_name TEXT NOT NULL, reason TEXT NOT NULL, info TEXT NOT NULL)')

    # Usuarios y sesiones persistentes. La primera cuenta solo se crea
    # localmente o a partir de secretos del servidor publicados de forma privada.
    global AUTH
    AUTH=CentralAuth(db_connect, LOCK, DATA)
    AUTH.initialize()


    # Relaciona automáticamente las prefichas importadas antiguas con su jefe.
    reconcile_imported_chiefs()
    # La regularización se ejecuta SOLO una vez por base de datos. Una revisión
    # manual posterior marcada como pendiente no se anula al reiniciar.
    regularize_official_reviews_once()


def setting(key):
    with db_connect() as c:
        row = c.execute('SELECT value FROM settings WHERE key=?', (key,)).fetchone()
    return row['value'] if row else None


def hash_pin(pin, salt=None):
    salt = salt or secrets.token_bytes(16)
    v = hashlib.pbkdf2_hmac('sha256', pin.encode('utf-8'), salt, 260_000)
    return salt.hex() + ':' + v.hex()


def verify_pin(pin, stored):
    try:
        salt, h = stored.split(':', 1)
        return hmac.compare_digest(hash_pin(pin, bytes.fromhex(salt)), stored)
    except Exception:
        return False


def now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def person_key(name):
    """Elimina títulos y diferencias cosméticas; exige coincidencia completa."""
    value=unicodedata.normalize('NFD', str(name or '').casefold())
    value=''.join(ch for ch in value if unicodedata.category(ch)!='Mn')
    value=re.sub(r'[^a-z0-9 ]+', ' ', value)
    value=re.sub(r'^(?:lic|licda|licdo|licenciado|licenciada|ing|ingeniero|ingeniera|dr|dra|doctor|doctora)\s+', '', ' '.join(value.split()))
    return ' '.join(value.split())


def clean_display_name(name):
    name=' '.join(str(name or '').strip().split())
    key=person_key(name)
    if not key:return ''
    title='Lic. ' if re.match(r'^\s*lic',name,re.I) else ('Ing. ' if re.match(r'^\s*ing',name,re.I) else '')
    return title+' '.join(part.capitalize() for part in key.split())


def upsert_person(c, name, identity='', stamp=None):
    """Mismo nombre completo e identidad compatible => misma persona maestra.
    Identidades distintas nunca se unen solo por nombre.
    """
    key=person_key(name);identity=str(identity or '').strip()
    if not key:return None
    matches=[]
    for row in c.execute("SELECT id,data FROM docs WHERE collection='personas'"):
        data=json.loads(row['data'])
        if person_key(data.get('nombre'))==key:matches.append((row['id'],data))
    picked=None
    if identity:
        picked=next(((i,d) for i,d in matches if str(d.get('identidad') or '').strip()==identity),None)
        if not picked and len(matches)==1 and not str(matches[0][1].get('identidad') or '').strip():picked=matches[0]
    else:
        unidentified=[(i,d) for i,d in matches if not str(d.get('identidad') or '').strip()]
        if len(unidentified)==1:picked=unidentified[0]
        elif len(matches)==1:picked=matches[0]
    if picked:
        id_,data=picked
        if identity and not data.get('identidad'):
            data['identidad']=identity
            c.execute('UPDATE docs SET data=?,updated=? WHERE collection=? AND id=?', (json.dumps(data,ensure_ascii=False),stamp or now(),'personas',id_))
        return id_
    id_=uuid.uuid4().hex
    data={'nombre':clean_display_name(name),'identidad':identity,'creadoEn':stamp or now()}
    c.execute('INSERT INTO docs(collection,id,data,updated) VALUES(?,?,?,?)', ('personas',id_,json.dumps(data,ensure_ascii=False),stamp or now()))
    return id_


def reconcile_imported_chiefs():
    """Migración idempotente de prefichas antiguas: responsables del Excel = jefaturas.
    Solo afecta empleados marcados importadoExcel y no cambia jefaturas incompatibles.
    """
    migrated=0
    with LOCK:
        with db_connect() as c:
            areas={r['id']:json.loads(r['data']) for r in c.execute("SELECT id,data FROM docs WHERE collection='areas'")}
            employees={r['id']:json.loads(r['data']) for r in c.execute("SELECT id,data FROM docs WHERE collection='empleados'")}
            rows=list(c.execute("SELECT id,data FROM docs WHERE collection='bienes'"))
            by_area={}
            for row in rows:
                b=json.loads(row['data'])
                e=employees.get(b.get('personaId')) if b.get('personaTipo')=='empleado' else None
                if not e or not e.get('importadoExcel') or not b.get('fuenteImportacion'):continue
                by_area.setdefault(b.get('areaId'),{}).setdefault(b.get('personaId'),[]).append((row['id'],b))
            stamp=now();modified=set()
            for area_id, people in by_area.items():
                area=areas.get(area_id)
                if not area or len({person_key(employees[x]['nombre']) for x in people})!=1:continue
                employee=employees[next(iter(people))]
                name=employee['nombre'];key=person_key(name)
                if area.get('jefeNombre') and person_key(area['jefeNombre'])!=key:
                    log_action(c,'jefatura_conflicto','areas',area_id,'Jefe de Excel distinto al jefe registrado; no se reasignó.')
                    continue
                master_id=upsert_person(c,name,employee.get('identidad',''),stamp)
                master=next(json.loads(r['data']) for r in c.execute("SELECT data FROM docs WHERE collection='personas' AND id=?",(master_id,)))
                area['jefeNombre']=master['nombre'];area['jefeIdentidad']=master.get('identidad','');area['jefePersonaId']=master_id
                c.execute('UPDATE docs SET data=?,updated=? WHERE collection=? AND id=?',(json.dumps(area,ensure_ascii=False),stamp,'areas',area_id))
                for eid, items in people.items():
                    for bid,b in items:
                        b['personaTipo']='jefe';b['personaId']=area_id
                        b.setdefault('revisado',False)
                        c.execute('UPDATE docs SET data=?,updated=? WHERE collection=? AND id=?',(json.dumps(b,ensure_ascii=False),stamp,'bienes',bid))
                        migrated+=1
                    modified.add(eid)
                log_action(c,'conciliar_jefatura','areas',area_id,f'{name}: {sum(len(x) for x in people.values())} bienes del Excel asociados al jefe')
            for eid in modified:
                # Preservar empleados con otras asignaciones no provenientes del Excel.
                other=any(json.loads(r['data']).get('personaTipo')=='empleado' and json.loads(r['data']).get('personaId')==eid for r in c.execute("SELECT data FROM docs WHERE collection='bienes'"))
                if not other and employees[eid].get('importadoExcel'):
                    c.execute('DELETE FROM docs WHERE collection=? AND id=?',('empleados',eid))
    return migrated



def regularize_official_reviews_once():
    """Marca el inventario existente como revisado documentalmente una sola vez.

    Es una decisión administrativa del usuario, NO una inspección física.
    No corrige números SIAFI, ubicaciones ni incidencias de importación.
    """
    flag='migracion_revision_documental_28'
    with LOCK:
        with db_connect() as c:
            if c.execute('SELECT 1 FROM settings WHERE key=?',(flag,)).fetchone():
                return 0
            stamp=now()
            updated=0
            for row in c.execute("SELECT id,data FROM docs WHERE collection='bienes'").fetchall():
                bien=json.loads(row['data'])
                if bien.get('revisado') is True:
                    continue
                bien['revisado']=True
                bien['revisionFecha']=stamp
                bien['revisionOrigen']='Regularización documental solicitada en NEXUS PRO 2.8'
                c.execute('UPDATE docs SET data=?,updated=? WHERE collection=? AND id=?',
                          (json.dumps(bien,ensure_ascii=False),stamp,'bienes',row['id']))
                updated+=1
            c.execute('INSERT INTO settings(key,value) VALUES(?,?)',(flag,stamp))
            if updated:
                log_action(c,'regularizacion_documental_28','bienes','',
                           f'{updated} bienes marcados revisados a solicitud del usuario; sin verificar condición física')
            return updated


def mark_reviewed(ids, reviewed):
    if not isinstance(ids,list) or not ids or len(ids)>12000 or not all(isinstance(x,str) and re.fullmatch('[0-9a-f]{32}',x) for x in ids):
        raise ValueError('Selecciona una lista válida de bienes (máximo 12.000).')
    ids=list(dict.fromkeys(ids));stamp=now()
    with LOCK:
        with db_connect() as c:
            for id_ in ids:
                row=c.execute("SELECT data FROM docs WHERE collection='bienes' AND id=?",(id_,)).fetchone()
                if row is None:raise ValueError('Se detectó un registro eliminado. Actualiza la pantalla y vuelve a seleccionar.')
                b=json.loads(row['data']);b['revisado']=bool(reviewed)
                b['revisionFecha']=stamp if reviewed else ''
                b['revisionOrigen']='Revisión manual' if reviewed else ''
                c.execute("UPDATE docs SET data=?,updated=? WHERE collection='bienes' AND id=?",(json.dumps(b,ensure_ascii=False),stamp,id_))
            log_action(c,'marcar_revisados' if reviewed else 'marcar_pendientes','bienes','',f'{len(ids)} bienes')
    return len(ids)


def doc_list(col):
    with db_connect() as c:
        rows = c.execute('SELECT id, data FROM docs WHERE collection=?', (col,)).fetchall()
    return [dict(id=r['id'], **json.loads(r['data'])) for r in rows]


def doc_get(col, id_):
    with db_connect() as c:
        row = c.execute('SELECT data FROM docs WHERE collection=? AND id=?', (col, id_)).fetchone()
    return json.loads(row['data']) if row else None


def log_action(c, action, col, id_, details=''):
    c.execute('INSERT INTO audit(date,action,collection,document_id,details) VALUES(?,?,?,?,?)', (now(), action, col, id_, details[:500]))


def clean_data(col, data, doc_id=None):
    if not isinstance(data, dict):
        raise ValueError('Datos inválidos.')
    data = {str(k): v for k,v in data.items() if not str(k).startswith('__') and k != 'id'}
    if len(json.dumps(data, ensure_ascii=False)) > 400_000:
        raise ValueError('Registro demasiado extenso.')
    if col == 'bienes':
        num = str(data.get('numeroInventario') or '').strip()
        desc = str(data.get('descripcion') or '').strip()
        if not num or not desc:
            raise ValueError('Número de inventario y descripción son obligatorios.')
        if len(num)>100 or len(desc)>1000:
            raise ValueError('El número o descripción es demasiado largo.')
        if not doc_get('areas',str(data.get('areaId') or '')):
            raise ValueError('Debes seleccionar un área existente.')
        for item in doc_list('bienes'):
            if item['id']!=doc_id and item.get('numeroInventario','').casefold()==num.casefold():
                raise ValueError('Ya existe un bien con ese número de inventario.')
        data['numeroInventario'] = num
        data['descripcion'] = desc
        data['estadoBueno'] = bool(data.get('estadoBueno', False))
        data['revisado'] = bool(data.get('revisado',False))
        if data.get('personaTipo') == 'empleado':
            p = doc_get('empleados', str(data.get('personaId') or ''))
            if not p or p.get('areaId')!=data['areaId']:
                raise ValueError('La persona asignada debe pertenecer al área del bien.')
        if data.get('personaTipo')=='jefe':
            data['personaId'] = data['areaId']
        if data.get('personaTipo') not in ('empleado','jefe'):
            data['personaTipo'] = None
            data['personaId'] = None
    elif col == 'areas':
        name = str(data.get('nombre') or '').strip()
        if not name or len(name)>180: raise ValueError('Escribe un nombre de área válido.')
        data['nombre'] = name
        current=doc_get('areas',doc_id) if doc_id else None
        if current and current.get('jefeNombre') and not str(data.get('jefeNombre') or '').strip():
            if any(b.get('areaId')==doc_id and b.get('personaTipo')=='jefe' for b in doc_list('bienes')):
                raise ValueError('No puedes quitar el jefe: tiene bienes bajo su responsabilidad. Designa antes un nuevo jefe.')
    elif col == 'empleados':
        name = str(data.get('nombre') or '').strip()
        if not name or len(name)>180: raise ValueError('Escribe el nombre del empleado.')
        if not doc_get('areas', str(data.get('areaId') or '')):
            raise ValueError('El empleado debe pertenecer a un área existente.')
        data['nombre'] = name
        for other in doc_list('empleados'):
            if other['id']!=doc_id and other.get('areaId')==data['areaId']:
                if person_key(other.get('nombre'))==person_key(name) or (data.get('identidad') and str(other.get('identidad') or '').strip()==str(data['identidad']).strip()):
                    raise ValueError('Esta persona ya está registrada como empleado del área.')
        area=doc_get('areas',data['areaId'])
        if area and area.get('jefeNombre') and person_key(area.get('jefeNombre'))==person_key(name):
            if not (data.get('identidad') and area.get('jefeIdentidad') and str(data['identidad']).strip()!=str(area['jefeIdentidad']).strip()):
                raise ValueError('Esta persona ya figura como jefa del área, no debes duplicarla como empleado.')
    return data


def save_doc(col, data, id_=None, is_update=False):
    with LOCK:
        if is_update:
            old = doc_get(col,id_)
            if old is None: raise ValueError('Registro no encontrado.')
            data = {**old, **data}
        data = clean_data(col,data,id_)
        id_ = id_ or uuid.uuid4().hex
        with db_connect() as c:
            if col=='areas':
                chief=str(data.get('jefeNombre') or '').strip()
                if chief:
                    pid=upsert_person(c,chief,data.get('jefeIdentidad',''))
                    p=c.execute("SELECT data FROM docs WHERE collection='personas' AND id=?",(pid,)).fetchone()
                    master=json.loads(p['data'])
                    data['jefePersonaId']=pid
                    data['jefeNombre']=master['nombre']
                    if not data.get('jefeIdentidad'):data['jefeIdentidad']=master.get('identidad','')
                else:data['jefePersonaId']=None
            if is_update:
                c.execute('UPDATE docs SET data=?,updated=? WHERE collection=? AND id=?', (json.dumps(data,ensure_ascii=False),now(),col,id_))
            else:
                c.execute('INSERT INTO docs(collection,id,data,updated) VALUES(?,?,?,?)', (col,id_,json.dumps(data,ensure_ascii=False),now()))
            log_action(c,'actualizar' if is_update else 'crear',col,id_,data.get('numeroInventario',data.get('nombre','')))
        return id_


def delete_doc(col,id_):
    """Eliminación transaccional; los bienes de un empleado pasan a la jefatura del área."""
    with LOCK:
        current=doc_get(col,id_)
        if current is None:raise ValueError('Registro no encontrado.')
        if col=='areas' and (any(x.get('areaId')==id_ for x in doc_list('bienes')) or any(x.get('areaId')==id_ for x in doc_list('empleados'))):
            raise ValueError('No se puede eliminar un área con empleados o bienes.')
        reassigned=0
        with db_connect() as c:
            if col=='empleados':
                area=doc_get('areas',current.get('areaId',''))
                assigned=[]
                for r in c.execute("SELECT id,data FROM docs WHERE collection='bienes'"):
                    b=json.loads(r['data'])
                    if b.get('personaTipo')=='empleado' and b.get('personaId')==id_:assigned.append((r['id'],b))
                if assigned and not (area and str(area.get('jefeNombre') or '').strip()):
                    raise ValueError('No se puede retirar al responsable porque el área no tiene jefe designado. Registra primero el jefe de área.')
                stamp=now()
                for bid,b in assigned:
                    b['personaTipo']='jefe';b['personaId']=b['areaId']
                    c.execute('UPDATE docs SET data=?,updated=? WHERE collection=? AND id=?', (json.dumps(b,ensure_ascii=False),stamp,'bienes',bid))
                    log_action(c,'traslado_automatico_jefe','bienes',bid,f"Responsable retirado: {current.get('nombre','')}; jefe: {area.get('jefeNombre','')}")
                    reassigned+=1
            if col=='personas' and any(x.get('jefePersonaId')==id_ for x in doc_list('areas')):
                raise ValueError('La persona dirige áreas. Primero cambia la jefatura del área.')
            c.execute('DELETE FROM docs WHERE collection=? AND id=?',(col,id_))
            log_action(c,'eliminar',col,id_,f'{reassigned} bienes reasignados a jefatura' if reassigned else '')
        return {'ok':True,'reasignados':reassigned}


def png_from_qr(text):
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=5, border=3)
    qr.add_data(text)
    qr.make(fit=True)
    cells = qr.get_matrix()
    scale=5
    n=len(cells)*scale
    rows=[]
    for line in cells:
        px=b''.join((b'\x00' if x else b'\xff')*scale for x in line)
        rows.extend([b'\x00'+px]*scale)
    def chunk(kind,data):
        return struct.pack('!I',len(data))+kind+data+struct.pack('!I',zlib.crc32(kind+data)&0xffffffff)
    return b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('!2I5B',n,n,8,0,0,0,0))+chunk(b'IDAT',zlib.compress(b''.join(rows),6))+chunk(b'IEND',b'')


def report_rows(area_id=None):
    areas={x['id']:x for x in doc_list('areas')}
    emps={x['id']:x for x in doc_list('empleados')}
    bienes=doc_list('bienes')
    if area_id: bienes=[b for b in bienes if b.get('areaId')==area_id]
    bienes.sort(key=lambda a:str(a.get('numeroInventario','')).casefold())
    columns=['N.º inventario','Descripción','N.º serie','Color','Estado','Estado original Excel','Área','A cargo de','Valor (L)','Fecha adquisición','Marca','Modelo','N.º ficha','N.º origen','Ubicación original SIAFI','Origen PDF','Página PDF','Revisión de inventario','Fecha revisión']
    rows=[]
    for b in bienes:
        area=areas.get(b.get('areaId'),{})
        p='Sin asignar'
        if b.get('personaTipo')=='jefe':p=area.get('jefeNombre','Jefe de área') or 'Jefe de área'
        elif b.get('personaTipo')=='empleado':p=emps.get(b.get('personaId'),{}).get('nombre','Sin asignar')
        rows.append([str(x or '') for x in [b.get('numeroInventario'),b.get('descripcion'),b.get('numeroSerie'),b.get('color'),'Buen estado' if b.get('estadoBueno') else 'Requiere revisión',b.get('estadoOriginal',''),area.get('nombre',''),p,b.get('precio',''),b.get('fechaAdquisicion',''),b.get('marca',''),b.get('modelo',''),b.get('numeroFicha',''),b.get('numeroInventarioOriginal',''),b.get('ubicacionSiafi',''),b.get('fuenteImportacionPDF',''),b.get('paginaPDF',''),'Revisado' if b.get('revisado') else 'Pendiente',b.get('revisionFecha','')]])
    return columns,rows


def xlsx_bytes(title,headers,rows):
    # Archivo Office Open XML completo, generado solamente con la biblioteca estándar.
    def cell(s): return '<c t="inlineStr"><is><t xml:space="preserve">'+xml_escape(str(s))+'</t></is></c>'
    sheetrows=[]
    for i, r in enumerate([headers]+rows,1):
        sheetrows.append('<row r="%d">%s</row>'%(i,''.join(map(cell,r))))
    sheet='<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>'+''.join(sheetrows)+'</sheetData></worksheet>'
    content_types='<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>'
    rels='<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>'
    workbook='<?xml version="1.0" encoding="UTF-8"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="'+xml_escape(re.sub(r'[\\/*?:\[\]]',' ',title)[:31] or 'Inventario')+'" sheetId="1" r:id="rId1"/></sheets></workbook>'
    xlrels='<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>'
    out=io.BytesIO()
    with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as z:
        for n,v in {'[Content_Types].xml':content_types,'_rels/.rels':rels,'xl/workbook.xml':workbook,'xl/_rels/workbook.xml.rels':xlrels,'xl/worksheets/sheet1.xml':sheet}.items():z.writestr(n,v)
    return out.getvalue()


def docx_bytes(title,headers,rows):
    def para(s,bold=False):
        return '<w:p><w:r>'+('<w:rPr><w:b/></w:rPr>' if bold else '')+'<w:t xml:space="preserve">'+xml_escape(str(s))+'</w:t></w:r></w:p>'
    def cell(s,bold=False):return '<w:tc><w:tcPr><w:tcW w:w="2200" w:type="dxa"/></w:tcPr>'+para(s,bold)+'</w:tc>'
    def row(a,bold=False):return '<w:tr>'+''.join(cell(s,bold) for s in a)+'</w:tr>'
    table='<w:tbl><w:tblPr><w:tblBorders><w:top w:val="single" w:sz="4"/><w:bottom w:val="single" w:sz="4"/><w:insideH w:val="single" w:sz="4"/><w:insideV w:val="single" w:sz="4"/></w:tblBorders></w:tblPr><w:tblGrid>'+''.join('<w:gridCol w:w="2200"/>' for _ in headers)+'</w:tblGrid>'+row(headers,True)+''.join(row(r) for r in rows)+'</w:tbl>'
    xml='<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>'+para(title,True)+table+'<w:sectPr><w:pgSz w:w="16838" w:h="11906" w:orient="landscape"/></w:sectPr></w:body></w:document>'
    types='<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>'
    rels='<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>'
    out=io.BytesIO()
    with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as z:
        z.writestr('[Content_Types].xml',types)
        z.writestr('_rels/.rels',rels)
        z.writestr('word/document.xml',xml)
    return out.getvalue()


def backup_bytes():
    out=io.BytesIO()
    with LOCK:
        with db_connect() as c:
            # backup() captura una vista consistente incluso si la aplicación está abierta.
            with sqlite3.connect(':memory:') as mem:
                c.backup(mem)
                disk=DATA/'_instant_backup.sqlite3'
                try:
                    with sqlite3.connect(str(disk)) as dst:mem.backup(dst)
                    b=disk.read_bytes()
                finally:
                    disk.unlink(missing_ok=True)
        with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as z:
            z.writestr('inventario.sqlite3',b)
            z.writestr('INFORMACION.txt','Copia de seguridad de Inventario HLMV. Incluye base de datos y fotografías.\n')
            for p in MEDIA.rglob('*'):
                if p.is_file():z.write(p,'imagenes/'+p.relative_to(MEDIA).as_posix())
    return out.getvalue()


def restore_backup(blob):
    if len(blob)>100*1024*1024:raise ValueError('Copia demasiado grande (máximo 100 MB).')
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        files=z.namelist()
        if 'inventario.sqlite3' not in files:raise ValueError('La copia no contiene una base de datos.')
        if any(not x.startswith('imagenes/') and x not in ('inventario.sqlite3','INFORMACION.txt') for x in files):
            raise ValueError('Copia contiene archivos no esperados.')
        sqlblob=z.read('inventario.sqlite3')
        if len(sqlblob)>70*1024*1024:raise ValueError('Base de datos demasiado grande.')
        check=DATA/'_validacion_restauracion.sqlite3'
        try:
            check.write_bytes(sqlblob)
            with sqlite3.connect(str(check)) as c:
                if c.execute('PRAGMA integrity_check').fetchone()[0]!='ok':raise ValueError('Base de datos dañada.')
                names={a[0] for a in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if not {'docs','settings','audit'}<=names:raise ValueError('Formato de copia no reconocido.')
            with LOCK:
                with db_connect() as live:
                    with sqlite3.connect(str(check)) as source:
                        source.backup(live)
                for name in files:
                    if name.startswith('imagenes/') and not name.endswith('/'):
                        filename=Path(name).name
                        if re.fullmatch(r'[A-Za-z0-9_.-]{1,100}',filename):
                            blobdata=z.read(name)
                            if len(blobdata)>8*1024*1024:raise ValueError('Imagen demasiado grande.')
                            (MEDIA/filename).write_bytes(blobdata)
                SESSIONS.clear()
                regularize_official_reviews_once()
        finally:check.unlink(missing_ok=True)



def excel_preview(blob,file_name='inventario.xlsx'):
    """Vista previa de todos los bienes, incluido SIAFI duplicado en la misma hoja.
    Nunca sustituye un SIAFI real ni sobrescribe otro bien.
    """
    parsed=parse_workbook(blob)
    existing=doc_list('bienes')
    by_number={str(x.get('numeroInventario','')).casefold():x for x in existing}
    by_source={(str(x.get('fuenteImportacion','')).casefold(),x.get('hojaExcel'),x.get('filaExcel')):x for x in existing if x.get('fuenteImportacion')}
    area_names={a['id']:a['nombre'] for a in doc_list('areas')}
    seen={}
    details=[]
    for item in parsed['bienes']:
        original=item['numeroInventario']
        key=original.casefold()
        source_key=(file_name.casefold(),item['hoja'],item['fila'])
        from_source=by_source.get(source_key)
        first=seen.get(key)
        old=by_number.get(key)
        previous_area=area_names.get(old.get('areaId'),'') if old else ''
        if from_source:
            status='ya_importado';reason='Fila ya registrada anteriormente.';other=from_source
        elif old and excel_norm(old.get('descripcion'))==excel_norm(item['descripcion']) and excel_norm(previous_area)==excel_norm(item['area']) and excel_norm(old.get('numeroSerie'))==excel_norm(item['numeroSerie']) and excel_norm(old.get('marca'))==excel_norm(item['marca']) and excel_norm(old.get('modelo'))==excel_norm(item['modelo']):
            status='ya_importado';reason='El bien ya figura en esta área con las mismas características.';other=old
        elif first and not item['pendienteNumero']:
            # Segunda fila con un SIAFI repetido DENTRO del mismo Excel:
            # crear ficha provisional para no perder el registro físico.
            status='nuevo_pendiente';reason='Número SIAFI repetido dentro del Excel; verificar con SIAFI.';other=first
        elif old or first:
            status='duplicado';reason='Número de inventario ya usado por otro registro; requiere revisión.';other=old or first
        else:
            status='nuevo';reason='';other=None
        seen.setdefault(key,item)
        detail={**item,'estadoImportacion':status,'motivo':reason}
        if status=='nuevo_pendiente':
            stable=hashlib.sha256(f'{file_name.casefold()}|{item["hoja"]}|{item["fila"]}|{original}|{excel_norm(item["descripcion"])}'.encode()).hexdigest()[:12].upper()
            detail['numeroInventario']=f'PEND-DUP-{stable}'
            detail['numeroOriginal']=original
            detail['pendienteNumero']=True
            detail['siafiDuplicado']=True
        if other and status in ('duplicado','nuevo_pendiente'):
            detail['ubicacionExistente']=other.get('area','') if first else previous_area
        details.append(detail)
    return {'total':len(details), 'nuevos':sum(x['estadoImportacion'] in ('nuevo','nuevo_pendiente') for x in details),
            'duplicados':sum(x['estadoImportacion'] in ('duplicado','nuevo_pendiente') for x in details),
            'yaImportados':sum(x['estadoImportacion']=='ya_importado' for x in details),
            'sinSIAFI':sum(x['pendienteNumero'] for x in details),
            'areas':list(dict.fromkeys(x['area'] for x in details)),
            'ignoradas':parsed['hojasIgnoradas'], 'filas':details}


def import_excel_bytes(blob,file_name='inventario.xlsx'):
    """Importación transaccional. Nunca sobrescribe bienes existentes."""
    if not re.fullmatch(r'[\w À-ÿ().,-]{1,120}\.xlsx',file_name or '',re.I):
        file_name='inventario.xlsx'
    with LOCK:
        plan=excel_preview(blob,file_name)
        stamp=now()
        accepted=[item for item in plan['filas'] if item['estadoImportacion'] in ('nuevo','nuevo_pendiente')]
        # Los responsables nombrados en prefichas Excel son jefes de área.
        # Se concilian contra una única persona maestra por nombre completo/identidad.
        with db_connect() as c:
            areas={excel_norm(json.loads(r['data']).get('nombre','')):(r['id'],json.loads(r['data'])) for r in c.execute("SELECT id,data FROM docs WHERE collection='areas'")}
            created_areas=0;created_people=0;chief_conflicts=0
            for row in accepted:
                area_name=row['area'];k=excel_norm(area_name)
                found=areas.get(k)
                if found is None:
                    area_id=uuid.uuid4().hex
                    area={'nombre':area_name,'jefeNombre':'','jefeIdentidad':'','creadoEn':stamp,'importadoExcel':True}
                    c.execute('INSERT INTO docs(collection,id,data,updated) VALUES(?,?,?,?)',('areas',area_id,json.dumps(area,ensure_ascii=False),stamp))
                    areas[k]=(area_id,area);created_areas+=1
                else:area_id,area=found
                person=row.get('responsable','').strip()
                chief_ok=False
                if person:
                    if area.get('jefeNombre') and person_key(area.get('jefeNombre'))!=person_key(person):
                        chief_conflicts+=1
                        # No se suplanta al jefe previamente designado.
                        log_action(c,'jefatura_conflicto','areas',area_id,f'Excel: {person}; ficha: {area.get("jefeNombre")}')
                    elif area.get('jefeIdentidad') and row.get('identidad') and area['jefeIdentidad']!=row['identidad']:
                        chief_conflicts+=1
                    else:
                        # Número de personas maestras antes de crear o relacionar.
                        existing_count=c.execute("SELECT COUNT(*) FROM docs WHERE collection='personas'").fetchone()[0]
                        pid=upsert_person(c,person,area.get('jefeIdentidad',''),stamp)
                        count=c.execute("SELECT COUNT(*) FROM docs WHERE collection='personas'").fetchone()[0]
                        created_people+=count-existing_count
                        master=json.loads(c.execute("SELECT data FROM docs WHERE collection='personas' AND id=?",(pid,)).fetchone()['data'])
                        area.update({'jefeNombre':master['nombre'],'jefeIdentidad':master.get('identidad',''),'jefePersonaId':pid})
                        c.execute('UPDATE docs SET data=?,updated=? WHERE collection=? AND id=?',(json.dumps(area,ensure_ascii=False),stamp,'areas',area_id))
                        chief_ok=True
                item={
                    'numeroInventario':row['numeroInventario'],'descripcion':row['descripcion'],
                    'numeroSerie':row['numeroSerie'],'color':row['color'],
                    'marca':row['marca'],'modelo':row['modelo'],
                    'numeroFicha':row['numeroFicha'],'precio':row['precio'],
                    'estadoBueno':row['estadoBueno'],'estadoOriginal':row['estadoOriginal'],
                    'areaId':area_id,'personaTipo':'jefe' if chief_ok else None,
                    'personaId':area_id if chief_ok else None, 'fotoURL':'', 'fechaAdquisicion':'','creadoEn':stamp,
                    'revisado':True,'revisionFecha':stamp,
                    'revisionOrigen':'Excel oficial: revisión documental',
                    'sinSIAFI':row['pendienteNumero'],'numeroInventarioOriginal':row['numeroOriginal'],
                    'siafiDuplicado':bool(row.get('siafiDuplicado')), 'revisionMotivo':row.get('motivo','') if row.get('siafiDuplicado') else ('Verificar jefe indicado en Excel' if person and not chief_ok else ''),
                    'fuenteImportacion':file_name,'hojaExcel':row['hoja'],'filaExcel':row['fila'],
                }
                document_id=uuid.uuid4().hex
                c.execute('INSERT INTO docs(collection,id,data,updated) VALUES(?,?,?,?)',('bienes',document_id,json.dumps(item,ensure_ascii=False),stamp))
            pending=0
            for row in plan['filas']:
                if row['estadoImportacion'] not in ('duplicado','nuevo_pendiente'):continue
                hashval=hashlib.sha256(json.dumps([file_name,row['hoja'],row['fila'],row['numeroInventario'],row['descripcion']],ensure_ascii=False).encode()).hexdigest()
                before=c.execute('SELECT 1 FROM import_reviews WHERE id=?',(hashval,)).fetchone()
                if before:continue
                same_source=False
                for previous in c.execute('SELECT info FROM import_reviews WHERE file_name=?',(file_name,)):
                    try:
                        prior=json.loads(previous['info'])
                        if prior.get('hoja')==row['hoja'] and prior.get('fila')==row['fila']:
                            same_source=True;break
                    except (ValueError,TypeError):pass
                if same_source:continue
                c.execute('INSERT INTO import_reviews(id,created,file_name,reason,info) VALUES(?,?,?,?,?)',
                          (hashval,stamp,file_name,row['motivo'],json.dumps(row,ensure_ascii=False)))
                pending+=1
            log_action(c,'importar_excel','bienes','',f'{file_name}: {len(accepted)} bienes, {plan["duplicados"]} SIAFI repetidos, {plan["sinSIAFI"]} pendientes de verificación')
        return {'ok':True,'importados':len(accepted),'duplicados':plan['duplicados'],'sinSIAFI':plan['sinSIAFI'],
                'areasCreadas':created_areas,'responsablesCreados':created_people,'jefaturasPorVerificar':chief_conflicts,
                'conflictosGuardados':pending,'totalOrigen':plan['total']}


def pdf_preview(blob,file_name='recibo_siafi.pdf',agrupacion='bloque'):
    """Vista previa de Recibo de Asignación SIAFI sin alterar ningún registro."""
    if agrupacion not in ('bloque','ubicaciones'):
        raise ValueError('Agrupación inválida.')
    parsed=parse_siafi_pdf(blob)
    existing=doc_list('bienes')
    by_siafi={str(b.get('numeroInventario','')).casefold():b for b in existing}
    seen=set()
    summary={'total':len(parsed['registros']),'paginas':parsed['paginas'],'nuevos':0,
             'yaImportados':0,'conflictos':0,'externos':0,'porRevisar':0,'importeNuevo':0,
             'ubicaciones':parsed['ubicaciones'],'responsables':[], 'filas':[]}
    people=set()
    for r in parsed['registros']:
        siafi=r['numeroInventario']
        key=siafi.casefold()
        issues=list(r['incidencias'])
        if r['responsable']:people.add(r['responsable'])
        if 'HOSPITAL LEONARDO' not in r['institucionOriginal']:
            state='externo';summary['externos']+=1
        elif issues or not siafi:
            state='pendiente';summary['porRevisar']+=1
        elif key in seen:
            state='conflicto';summary['conflictos']+=1;issues.append('SIAFI repetido en el mismo PDF')
        elif key in by_siafi:
            state='ya_importado';summary['yaImportados']+=1
        else:
            state='nuevo';summary['nuevos']+=1
            summary['importeNuevo']+=r['precio'] or 0
        seen.add(key)
        summary['filas'].append({**r,'estadoImportacion':state,'motivo':'; '.join(issues)})
    summary['responsables']=sorted(people)
    summary['importeNuevo']=round(summary['importeNuevo'],2)
    summary['agrupacion']=agrupacion
    summary['avisos']=parsed['avisos']
    return summary


def import_pdf_bytes(blob,file_name='recibo_siafi.pdf',agrupacion='bloque'):
    """Carga idempotente, transaccional y NO destructiva del reporte PDF de SIAFI.
    No asigna jefaturas por suposición: PDF identifica a un responsable, no a jefe.
    La agrupación 'Bloque Quirúrgico' la solicita el usuario; se conserva la
    oficina declarada por SIAFI y se marca para comprobación física.
    """
    if not file_name.lower().endswith('.pdf'):raise ValueError('Solo se admiten PDF.')
    with LOCK:
        plan=pdf_preview(blob,file_name,agrupacion)
        stamp=now();new=[r for r in plan['filas'] if r['estadoImportacion']=='nuevo']
        with db_connect() as c:
            area_map={pdf_norm(json.loads(r['data']).get('nombre')):(r['id'],json.loads(r['data'])) for r in c.execute("SELECT id,data FROM docs WHERE collection='areas'")}
            employee_map={(pdf_norm(json.loads(r['data']).get('nombre')),json.loads(r['data']).get('areaId')):r['id'] for r in c.execute("SELECT id,data FROM docs WHERE collection='empleados'")}
            created_areas=0;created_employees=0
            for r in new:
                area_name=('Bloque Quirúrgico' if agrupacion=='bloque' else (r['oficinaOriginal'] or 'Ubicación PDF por verificar'))
                norm_area=pdf_norm(area_name)
                if norm_area in area_map:area_id,area_obj=area_map[norm_area]
                else:
                    area_id=uuid.uuid4().hex
                    area_obj={'nombre':area_name,'jefeNombre':'','jefeIdentidad':'','creadoEn':stamp,'importadoPDF':True}
                    c.execute('INSERT INTO docs(collection,id,data,updated) VALUES(?,?,?,?)',('areas',area_id,json.dumps(area_obj,ensure_ascii=False),stamp))
                    area_map[norm_area]=(area_id,area_obj);created_areas+=1
                responsibility=pdf_norm(r['responsable'])
                person_id=None
                if responsibility:
                    master=upsert_person(c,r['responsable'],r['identidadResponsable'],stamp)
                    emp_key=(responsibility,area_id)
                    if emp_key not in employee_map:
                        emp_id=uuid.uuid4().hex
                        emp={'nombre':r['responsable'],'identidad':r['identidadResponsable'], 'areaId':area_id,
                             'personaMaestraId':master,'creadoEn':stamp,'importadoPDF':True}
                        c.execute('INSERT INTO docs(collection,id,data,updated) VALUES(?,?,?,?)',('empleados',emp_id,json.dumps(emp,ensure_ascii=False),stamp))
                        employee_map[emp_key]=emp_id;created_employees+=1
                    person_id=employee_map[emp_key]
                item={
                    'numeroInventario':r['numeroInventario'],
                    'descripcion':r['descripcion'],'numeroSerie':r['numeroSerie'],
                    'numeroFicha':r['numeroFicha'],'codigoItemSiafi':r['codigoItemSiafi'],
                    'numeroInventarioAnterior':r['numeroInventarioAnterior'],
                    'marca':r['marca'],'modelo':r.get('modelo',''),'color':r['color'],'precio':r['precio'],
                    'estadoBueno':False,'estadoOriginal':'No consta estado físico en PDF',
                    'revisado':True,'revisionFecha':stamp,
                    'revisionOrigen':'PDF SIAFI oficial: revisión documental',
                    'estadoFisicoPorVerificar':True,
                    'areaId':area_id,'personaTipo':'empleado' if person_id else None,
                    'personaId':person_id,'fechaAdquisicion':'','fotoURL':'','creadoEn':stamp,
                    'fuenteImportacionPDF':file_name,'paginaPDF':r['paginaPDF'],
                    'ubicacionSiafi':r['oficinaOriginal'],'departamentoSiafi':r['departamentoOriginal'],
                    'institucionSiafi':r['institucionOriginal'],
                    'sectorOperativo':'Bloque Quirúrgico (clasificación solicitada)' if agrupacion=='bloque' else '',
                    'ubicacionFisicaPendiente':agrupacion=='bloque',
                    'responsableDocumentoSiafi':r['responsable'],
                }
                bid=uuid.uuid4().hex
                c.execute('INSERT INTO docs(collection,id,data,updated) VALUES(?,?,?,?)',('bienes',bid,json.dumps(item,ensure_ascii=False),stamp))
            registered=0
            for r in plan['filas']:
                if r['estadoImportacion'] not in ('externo','pendiente','conflicto'):continue
                info={'numeroInventario':r['numeroInventario'],'numeroFicha':r['numeroFicha'],
                      'descripcion':r['descripcion'],'area':r['oficinaOriginal'],
                      'paginaPDF':r['paginaPDF'],'estadoImportacion':r['estadoImportacion'],
                      'institucionSiafi':r['institucionOriginal']}
                rid=hashlib.sha256((r['numeroFicha']+'|'+r['numeroInventario']+'|'+r['institucionOriginal']).encode()).hexdigest()
                if not c.execute('SELECT 1 FROM import_reviews WHERE id=?',(rid,)).fetchone():
                    c.execute('INSERT INTO import_reviews(id,created,file_name,reason,info) VALUES(?,?,?,?,?)',
                              (rid,stamp,file_name,r['motivo'] or 'Pendiente de validación',json.dumps(info,ensure_ascii=False)))
                    registered+=1
            log_action(c,'importar_pdf_siafi','bienes','',f'{file_name}: {len(new)} nuevos, {plan["externos"]} externos, {plan["yaImportados"]} ya registrados')
        return {'ok':True,'importados':len(new),'totalOrigen':plan['total'],
                'yaImportados':plan['yaImportados'],'externos':plan['externos'],
                'conflictos':plan['conflictos'],'pendientes':plan['porRevisar'],
                'revisionesGuardadas':registered,'areasCreadas':created_areas,
                'responsablesCreados':created_employees}


class Handler(BaseHTTPRequestHandler):
    server_version='InventarioHLMV/1.0'
    def log_message(self, fmt,*args):
        if not self.path.startswith('/api/status'):
            print('[%s] %s'%(self.log_date_time_string(),fmt%args))
    def send_bytes(self,b,ctype='application/json; charset=utf-8',code=200,filename=None):
        self.send_response(code)
        self.send_header('Content-Type',ctype)
        self.send_header('Content-Length',str(len(b)))
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Frame-Options','DENY')
        self.send_header('Referrer-Policy','same-origin')
        if filename:self.send_header('Content-Disposition','attachment; filename="'+filename+'"')
        self.end_headers()
        try:self.wfile.write(b)
        except (ConnectionAbortedError,BrokenPipeError):pass
    def send_json(self,obj,code=200):self.send_bytes(json.dumps(obj,ensure_ascii=False).encode(),'application/json; charset=utf-8',code)
    def fail(self,code,msg):self.send_json({'error':msg},code)
    def cookie_token(self):
        c=SimpleCookie()
        try:c.load(self.headers.get('Cookie',''))
        except Exception:return None
        return c['hlmv_session'].value if 'hlmv_session' in c else None
    def current_user(self):
        return AUTH.authenticated(self.cookie_token()) if AUTH else None
    def auth(self):
        return self.current_user() is not None
    def is_local(self):return self.client_address[0] in ('127.0.0.1','::1')
    def require_auth(self):
        if not self.auth():
            self.fail(401,'Inicia sesión con tu cuenta del inventario.')
            return False
        return True
    def require_role(self,*roles):
        u=self.current_user()
        if not u:
            self.fail(401,'Inicia sesión con tu cuenta del inventario.')
            return False
        if u['role'] not in roles:
            self.fail(403,'Tu perfil no está autorizado para esta operación.')
            return False
        return True
    def body(self):
        length=int(self.headers.get('Content-Length','0'))
        if length>MAX_BODY:raise ValueError('Archivo o solicitud demasiado grande (máximo 12 MB).')
        return self.rfile.read(length)
    def json_body(self):return json.loads(self.body().decode('utf-8'))
    def do_GET(self):
        try:self.handle_get()
        except (ValueError,KeyError,sqlite3.Error) as e:self.fail(400,str(e))
        except Exception as e:print('Error GET',repr(e));self.fail(500,'Error interno. Revisa la consola de la aplicación.')
    def do_POST(self):
        try:self.handle_write('POST')
        except (ValueError,KeyError,sqlite3.Error) as e:self.fail(400,str(e))
        except Exception as e:print('Error POST',repr(e));self.fail(500,'Error interno. Revisa la consola.')
    def do_PUT(self):
        try:self.handle_write('PUT')
        except (ValueError,KeyError,sqlite3.Error) as e:self.fail(400,str(e))
        except Exception as e:print('Error PUT',repr(e));self.fail(500,'Error interno. Revisa la consola.')
    def do_DELETE(self):
        try:self.handle_write('DELETE')
        except (ValueError,KeyError,sqlite3.Error) as e:self.fail(400,str(e))
        except Exception as e:print('Error DELETE',repr(e));self.fail(500,'Error interno. Revisa la consola.')
    def handle_get(self):
        u=urlsplit(self.path); path=unquote(u.path); args=parse_qs(u.query)
        if path in ('/','/index.html'):
            return self.send_bytes((ROOT/'index.html').read_bytes(),'text/html; charset=utf-8')
        # Recursos de instalación PWA públicos. Ningún dato privado se guarda en caché.
        public_assets = {
            '/manifest.webmanifest': ('manifest.webmanifest','application/manifest+json; charset=utf-8'),
            '/pro.css': ('pro.css','text/css; charset=utf-8'),
            '/pro.js': ('pro.js','application/javascript; charset=utf-8'),
            '/customize.css': ('customize.css','text/css; charset=utf-8'),
            '/minimal.css': ('minimal.css','text/css; charset=utf-8'),
            '/customize.js': ('customize.js','application/javascript; charset=utf-8'),
            '/sw.js': ('sw.js','application/javascript; charset=utf-8'),
            '/icons/icon-192.png': ('icons/icon-192.png','image/png'),
            '/icons/icon-512.png': ('icons/icon-512.png','image/png'),
        }
        if path in public_assets:
            filename,mime=public_assets[path]
            return self.send_bytes((BASE/filename).read_bytes(),mime)
        if path=='/api/status':
            identity=self.current_user()
            return self.send_json({'initialized':AUTH.has_users(),'authenticated':bool(identity),'user':identity,'lan':LAN_MODE,'lanUrl':lan_url(self.server.server_port) if LAN_MODE else None,'version':'3.2','publicUrl':os.environ.get('HLMV_PUBLIC_URL','').strip().rstrip('/')})
        if path=='/api/health':return self.send_json({'ok':True})
        if path.startswith('/imagenes/'):
            filename=path.removeprefix('/imagenes/')
            if not re.fullmatch('[A-Za-z0-9_.-]{1,100}',filename):return self.fail(404,'No encontrado')
            if not self.require_auth():return
            f=MEDIA/filename
            if not f.is_file():return self.fail(404,'Imagen no encontrada.')
            ext=f.suffix.lower()
            typ={'.jpg':'image/jpeg','.jpeg':'image/jpeg','.png':'image/png','.webp':'image/webp','.gif':'image/gif'}.get(ext,'application/octet-stream')
            return self.send_bytes(f.read_bytes(),typ)
        if not self.require_auth():return
        if path=='/api/list':
            col=args.get('col',[''])[0]
            if col not in VALID_COL:return self.fail(400,'Colección no permitida.')
            items=doc_list(col)
            fld=args.get('field',[''])[0];val=args.get('value',[''])[0]
            if fld:items=[x for x in items if str(x.get(fld,''))==val]
            order=args.get('order',[''])[0]
            if order:items.sort(key=lambda x: str(x.get(order,'')).casefold())
            limit=int(args.get('limit',[str(len(items))])[0])
            return self.send_json({'docs':items[:limit],'size':len(items)})
        if path=='/api/doc':
            col=args.get('col',[''])[0];id_=args.get('id',[''])[0]
            if col not in VALID_COL:return self.fail(400,'Colección no permitida.')
            v=doc_get(col,id_)
            return self.send_json({'exists':v is not None,'id':id_,'data':v})
        if path=='/api/qr':
            numero=args.get('numero',[''])[0]
            if not any(b.get('numeroInventario')==numero for b in doc_list('bienes')):return self.fail(404,'Bien inexistente.')
            # Siempre usar el dominio público fijo cuando esté configurado.
            # Nunca incluir en etiquetas permanentes 'localhost' ni IPs locales.
            public=os.environ.get('HLMV_PUBLIC_URL','').strip().rstrip('/')
            if public:
                base=public
            else:
                # Solo desarrollo local: aún NO son QR permanentes.
                base='http://'+self.headers.get('Host','127.0.0.1:8895')
            url=base+'/index.html#/bien/'+quote(numero,safe='')
            return self.send_bytes(png_from_qr(url),'image/png')
        if path=='/api/export':
            area_id=args.get('areaId',[''])[0] or None
            ext=args.get('format',['xlsx'])[0]
            if ext not in ('xlsx','docx'):return self.fail(400,'Formato no admitido.')
            area=doc_get('areas',area_id) if area_id else None
            if area_id and area is None:return self.fail(404,'Área no encontrada.')
            headers,rows=report_rows(area_id)
            title='Inventario · '+area['nombre'] if area else 'Inventario general del hospital'
            data=xlsx_bytes(title,headers,rows) if ext=='xlsx' else docx_bytes(title,headers,rows)
            mime={'xlsx':'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet','docx':'application/vnd.openxmlformats-officedocument.wordprocessingml.document'}[ext]
            return self.send_bytes(data,mime,filename='inventario-hlmv-'+('area' if area_id else 'general')+'.'+ext)
        if path=='/api/backup':
            if not self.require_role('administrador'):return
            return self.send_bytes(backup_bytes(),'application/zip',filename='respaldo-inventario-hlmv-'+datetime.now().strftime('%Y%m%d')+'.zip')
        if path=='/api/import/review':
            if not self.require_role('administrador','inspector'):return
            with db_connect() as c:
                rows=c.execute('SELECT created,file_name,reason,info FROM import_reviews ORDER BY created DESC LIMIT 300').fetchall()
            return self.send_json({'pendientes':[{**json.loads(x['info']), 'fecha':x['created'], 'archivo':x['file_name'], 'motivo':x['reason']} for x in rows]})
        if path=='/api/audit':
            if not self.require_role('administrador','inspector'):return
            with db_connect() as c:r=c.execute('SELECT * FROM audit ORDER BY seq DESC LIMIT 200').fetchall()
            return self.send_json({'events':[dict(x) for x in r]})
        if path=='/api/users':
            if not self.require_role('administrador'):return
            return self.send_json({'users':AUTH.list_users()})
        self.fail(404,'Ruta no encontrada.')
    def handle_write(self,verb):
        path=urlsplit(self.path).path
        # Protección contra peticiones de sitios ajenos (CSRF).
        origin=self.headers.get('Origin')
        if origin:
            host=self.headers.get('Host','')
            if urlsplit(origin).netloc!=host:return self.fail(403,'Origen no permitido.')
        if path=='/api/setup' and verb=='POST':
            if os.environ.get('HLMV_CLOUD_MODE')=='1' or os.environ.get('HLMV_PUBLIC_URL','').strip():
                return self.fail(403,'Configura el administrador inicial en la PC privada o con secretos del servidor.')
            if LAN_MODE or not self.is_local() or self.headers.get('Host','').split(':')[0].lower() not in ('localhost','127.0.0.1','[::1]'):
                return self.fail(403,'La cuenta inicial solo se crea desde localhost en modo privado.')
            data=self.json_body()
            try:
                identity=AUTH.bootstrap_local(data.get('username',''),data.get('name',''),data.get('password',''))
            except ValueError as e:return self.fail(400,str(e))
            return self.issue_session(identity)
        if path=='/api/login' and verb=='POST':
            ip=self.client_address[0]
            data=self.json_body()
            username=str(data.get('username','')).strip().lower()
            key=ip+'|'+username
            recent=[t for t in FAILED_LOGINS.get(key,[]) if time.time()-t<LOGIN_WINDOW]
            FAILED_LOGINS[key]=recent
            if len(recent)>=LOGIN_MAX_FAILURES:return self.fail(429,'Demasiados intentos. Intenta más tarde.')
            token=AUTH.login(username,str(data.get('password','')))
            if not token:
                recent.append(time.time());FAILED_LOGINS[key]=recent
                time.sleep(.35)
                return self.fail(401,'Usuario o contraseña incorrectos.')
            FAILED_LOGINS.pop(key,None)
            return self.issue_session(token=token)
        if path=='/api/logout' and verb=='POST':
            AUTH.logout(self.cookie_token())
            self.send_response(200)
            self.send_header('Set-Cookie','hlmv_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0')
            self.send_header('Content-Length','2');self.end_headers();self.wfile.write(b'{}')
            return
        if path=='/api/users' and verb in ('POST','PUT'):
            if not self.require_role('administrador'):return
            b=self.json_body()
            if verb=='POST':
                id_=AUTH.add_user(b.get('username',''),b.get('name',''),b.get('password',''),b.get('role','consulta'))
                with db_connect() as c:log_action(c,'crear_usuario','usuarios',id_,f'Usuario: {str(b.get("username",""))[:40]} / Rol: {str(b.get("role",""))[:20]}')
                return self.send_json({'ok':True,'id':id_})
            user_id=str(b.get('id',''))
            AUTH.modify_user(user_id,b,self.current_user()['id'])
            with db_connect() as c:log_action(c,'modificar_usuario','usuarios',user_id,'Cambios de acceso o permisos')
            return self.send_json({'ok':True})
        if path=='/api/password' and verb=='POST':
            if not self.require_auth():return
            b=self.json_body();user=self.current_user()
            if not AUTH.check_password(user['id'],str(b.get('actual',''))):return self.fail(403,'La contraseña actual es incorrecta.')
            AUTH.modify_user(user['id'],{'password':str(b.get('nueva',''))},user['id'])
            return self.send_json({'ok':True,'relogin':True})
        if not self.require_auth():return
        if path in ('/api/import/pdf/preview','/api/import/pdf/commit') and verb=='POST':
            if not self.require_role('administrador','inspector'):return
            name=unquote(self.headers.get('X-Filename','recibo_siafi.pdf'))
            mode=self.headers.get('X-PDF-Agrupacion','bloque')
            if not name.lower().endswith('.pdf') or len(name)>160:
                return self.fail(400,'Selecciona un archivo PDF válido.')
            raw=self.body()
            if not raw or len(raw)>MAX_BODY:return self.fail(400,'PDF vacío o demasiado grande.')
            if path.endswith('/preview'):
                return self.send_json(pdf_preview(raw,name,mode))
            return self.send_json(import_pdf_bytes(raw,name,mode))
        if path in ('/api/import/preview','/api/import/commit') and verb=='POST':
            if not self.require_role('administrador','inspector'):return
            name=unquote(self.headers.get('X-Filename','inventario.xlsx'))
            if not name.lower().endswith('.xlsx'):
                return self.fail(400,'Solo se admiten archivos .xlsx.')
            raw=self.body()
            if not raw or len(raw)>MAX_BODY:return self.fail(400,'Archivo no válido o demasiado grande.')
            if path.endswith('/preview'):
                return self.send_json(excel_preview(raw,name))
            return self.send_json(import_excel_bytes(raw,name))
        if path=='/api/bienes/revision' and verb=='POST':
            if not self.require_role('administrador','inspector'):return
            b=self.json_body()
            return self.send_json({'ok':True,'actualizados':mark_reviewed(b.get('ids'),b.get('revisado',True))})
        if path=='/api/doc':
            if verb=='DELETE':
                if not self.require_role('administrador'):return
            elif not self.require_role('administrador','inspector'):return
            b=self.json_body() if verb!='DELETE' else self.json_body()
            col=str(b.get('col') or '');id_=str(b.get('id') or '')
            if col not in VALID_COL:return self.fail(400,'Colección no permitida.')
            if col=='hospital' and not self.require_role('administrador'):return
            if verb=='POST':
                return self.send_json({'id':save_doc(col,b.get('data',{}),id_ if (col=='hospital' and id_=='info') else None)})
            if not id_ or len(id_)>100:return self.fail(400,'ID no válido.')
            if verb=='PUT':return self.send_json({'id':save_doc(col,b.get('data',{}),id_,True)})
            if verb=='DELETE':return self.send_json(delete_doc(col,id_))
        if path=='/api/photo' and verb=='POST':
            if not self.require_role('administrador','inspector'):return
            b=self.json_body();raw=str(b.get('data') or '')
            data=base64.b64decode(raw,validate=True)
            if not 0<len(data)<=7*1024*1024:return self.fail(400,'La imagen debe pesar menos de 7 MB.')
            # Validación de firma: rechaza archivos que no son fotografías.
            if data.startswith(b'\xff\xd8\xff'):ext='.jpg'
            elif data.startswith(b'\x89PNG\r\n\x1a\n'):ext='.png'
            elif data.startswith(b'RIFF') and data[8:12]==b'WEBP':ext='.webp'
            elif data.startswith(b'GIF87a') or data.startswith(b'GIF89a'):ext='.gif'
            else:return self.fail(400,'Solo se permiten imágenes JPG, PNG, WebP o GIF.')
            name=uuid.uuid4().hex+ext
            (MEDIA/name).write_bytes(data)
            return self.send_json({'url':'/imagenes/'+name})
        if path=='/api/restore' and verb=='POST':
            if not self.require_role('administrador'):return
            b=self.json_body()
            if not AUTH.check_password(self.current_user()['id'],str(b.get('pin',''))):return self.fail(403,'Contraseña de administrador incorrecta.')
            raw=base64.b64decode(str(b.get('data') or ''),validate=True)
            result=AUTH.import_legacy_zip(raw,self.current_user())
            return self.send_json({'ok':True,'importacion':result,'relogin':False})
        self.fail(404,'Ruta no encontrada.')
    def issue_session(self,identity=None,token=None):
        if token is None:
            token=AUTH.open_session(identity['id'])
        user=AUTH.authenticated(token)
        if not user:return self.fail(500,'No se pudo crear la sesión.')
        body=json.dumps({'ok':True,'user':user},ensure_ascii=False).encode('utf-8')
        self.send_response(200)
        proto=self.headers.get('X-Forwarded-Proto','').lower()
        secure='; Secure' if (os.environ.get('HLMV_CLOUD_MODE')=='1' or proto=='https') else ''
        self.send_header('Set-Cookie','hlmv_session='+token+'; HttpOnly; SameSite=Strict; Path=/; Max-Age='+str(SESSION_SECONDS)+secure)
        self.send_header('Content-Type','application/json; charset=utf-8')
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Content-Length',str(len(body)))
        self.end_headers();self.wfile.write(body)


def lan_url(port):
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
            sock.connect(('1.1.1.1',80))
            ip=sock.getsockname()[0]
    except OSError:
        ip='127.0.0.1'
    return f'http://{ip}:{port}'


def main():
    global LAN_MODE
    p=argparse.ArgumentParser()
    p.add_argument('--lan', action='store_true',help='Compartir en la red local; usar solo en Wi-Fi institucional confiable')
    p.add_argument('--port', type=int, default=8765)
    p.add_argument('--no-browser',action='store_true')
    a=p.parse_args();LAN_MODE=a.lan
    init_db()
    # Nueva instalación limpia: nunca insertar archivos de ejemplo al arrancar.
    address='0.0.0.0' if a.lan else '127.0.0.1'
    server=ThreadingHTTPServer((address,a.port),Handler)
    url=f'http://127.0.0.1:{a.port}/'
    print('\n'+'='*58)
    print('  HOSPITAL LEONARDO MARTÍNEZ VALENZUELA')
    print('  SISTEMA LOCAL DE BIENES NACIONALES')
    print('='*58)
    print('Abrir en esta computadora:',url)
    print('Base de datos:',DB_PATH)
    if a.lan:
        print('Acceso desde móviles (misma red):',lan_url(a.port)+'/')
        print('ATENCIÓN: usar únicamente en red institucional confiable.')
    else:print('Modo privado: solo esta computadora (QR en teléfono requiere modo red).')
    print('Para detener el programa: CTRL+C o cierra esta ventana.')
    print('='*58+'\n')
    if not a.no_browser:
        threading.Timer(1.0,lambda:webbrowser.open(url)).start()
    try:server.serve_forever()
    except KeyboardInterrupt:pass
    finally:server.server_close()


if __name__=='__main__':main()
