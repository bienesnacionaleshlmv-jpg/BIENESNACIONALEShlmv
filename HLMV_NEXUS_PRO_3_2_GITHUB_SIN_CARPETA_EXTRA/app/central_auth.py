"""Usuarios, sesiones y migración seguros para HLMV NEXUS CENTRAL.

Se usa con el servidor HTTP existente; ninguna contraseña se guarda en texto plano.
Un único proceso de servidor debe compartir un único volumen SQLite persistente.
"""
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import threading
import time
import uuid
import zipfile
from datetime import datetime, timezone

SESSION_SECONDS = 8 * 3600
ROLES = ('administrador', 'inspector', 'consulta')
USER_PATTERN = re.compile(r'^[A-Za-z0-9._-]{3,40}$')


def password_hash(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac('sha256', str(password).encode(), salt, 380_000)
    return f'{salt.hex()}:{digest.hex()}'


def password_ok(password, saved):
    try:
        salt, _ = saved.split(':', 1)
        return hmac.compare_digest(password_hash(password, bytes.fromhex(salt)), saved)
    except (ValueError, TypeError):
        return False


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


class CentralAuth:
    def __init__(self, db_connect, lock, data_folder):
        self.connect = db_connect
        self.lock = lock
        self.data_folder = Path(data_folder)

    def initialize(self):
        with self.connect() as c:
            c.execute('''CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY, username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                name TEXT NOT NULL, password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('administrador','inspector','consulta')),
                active INTEGER NOT NULL DEFAULT 1, created TEXT NOT NULL)''')
            c.execute('''CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL,
                expires_at INTEGER NOT NULL, FOREIGN KEY (user_id) REFERENCES users(id))''')
            c.execute('CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at)')
            cols = {row['name'] for row in c.execute('PRAGMA table_info(docs)')}
            if 'version' not in cols:
                c.execute('ALTER TABLE docs ADD COLUMN version INTEGER NOT NULL DEFAULT 1')
        with self.lock:
            with self.connect() as c:
                exists = c.execute('SELECT 1 FROM users LIMIT 1').fetchone()
                if not exists:
                    username = os.getenv('HLMV_ADMIN_USER', '').strip().lower()
                    password = os.getenv('HLMV_ADMIN_PASSWORD', '')
                    if not username and not password and os.getenv('HLMV_CLOUD_MODE') != '1':
                        return
                    if not USER_PATTERN.fullmatch(username):
                        raise RuntimeError('Falta HLMV_ADMIN_USER: usuario de 3-40 caracteres (letras, números, punto, guion).')
                    if (len(password) < 12 or len(password) > 128 or any(x in password.lower() for x in ('cambiar_esta', 'crea_aqui_', 'pon_aqui_', 'password123456', 'clave_de_prueba'))):
                        raise RuntimeError('Falta HLMV_ADMIN_PASSWORD: define una clave privada de 12-128 caracteres.')
                    c.execute('INSERT INTO users VALUES (?,?,?,?,?,?,?)',
                              (uuid.uuid4().hex, username, 'Administración HLMV', password_hash(password), 'administrador', 1, utc_now()))

    def has_users(self):
        with self.connect() as c:
            return c.execute('SELECT 1 FROM users LIMIT 1').fetchone() is not None

    def open_session(self, user_id):
        token=secrets.token_urlsafe(36)
        with self.connect() as c:
            c.execute('DELETE FROM sessions WHERE expires_at<?',(int(time.time()),))
            c.execute('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)',
                (hashlib.sha256(token.encode()).hexdigest(),user_id,int(time.time())+SESSION_SECONDS))
        return token

    def bootstrap_local(self, username, name, password):
        username=str(username).strip().lower()
        name=str(name).strip()
        if not USER_PATTERN.fullmatch(username):
            raise ValueError('El usuario debe tener entre 3 y 40 caracteres (letras, números, puntos y guiones).')
        if not name or len(name)>120:raise ValueError('Escribe el nombre del administrador.')
        if len(str(password))<12 or len(str(password))>128:raise ValueError('La contraseña debe tener entre 12 y 128 caracteres.')
        with self.lock:
            with self.connect() as c:
                if c.execute('SELECT 1 FROM users LIMIT 1').fetchone():
                    raise ValueError('El administrador ya está configurado.')
                user_id=uuid.uuid4().hex
                c.execute('INSERT INTO users VALUES (?,?,?,?,?,?,?)',
                   (user_id,username,name,password_hash(password),'administrador',1,utc_now()))
        return self.get_user(user_id)

    def get_user(self, user_id):
        with self.connect() as c:
            r = c.execute('SELECT id,username,name,role,active FROM users WHERE id=?', (user_id,)).fetchone()
        return dict(r) if r and r['active'] else None

    def authenticated(self, token):
        if not token:
            return None
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        with self.connect() as c:
            r = c.execute('''SELECT u.id,u.username,u.name,u.role,u.active,s.expires_at
                             FROM sessions s JOIN users u ON u.id=s.user_id
                             WHERE s.token_hash=?''', (token_hash,)).fetchone()
            if not r:
                return None
            if not r['active'] or r['expires_at'] < int(time.time()):
                c.execute('DELETE FROM sessions WHERE token_hash=?', (token_hash,))
                return None
        return {'id': r['id'], 'username': r['username'], 'name': r['name'], 'role': r['role']}

    def login(self, username, password):
        with self.connect() as c:
            r = c.execute('SELECT * FROM users WHERE username=?', (str(username).lower().strip(),)).fetchone()
        if not r or not r['active'] or not password_ok(password, r['password_hash']):
            return None
        token = secrets.token_urlsafe(36)
        with self.connect() as c:
            c.execute('DELETE FROM sessions WHERE expires_at<?', (int(time.time()),))
            c.execute('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)',
                      (hashlib.sha256(token.encode()).hexdigest(), r['id'], int(time.time()) + SESSION_SECONDS))
        return token

    def check_password(self, user_id, password):
        with self.connect() as c:
            r = c.execute('SELECT password_hash,active FROM users WHERE id=?', (user_id,)).fetchone()
        return bool(r and r['active'] and password_ok(password, r['password_hash']))

    def logout(self, token):
        if not token:
            return
        with self.connect() as c:
            c.execute('DELETE FROM sessions WHERE token_hash=?', (hashlib.sha256(token.encode()).hexdigest(),))

    def list_users(self):
        with self.connect() as c:
            rows = c.execute('SELECT id,username,name,role,active,created FROM users ORDER BY username').fetchall()
        return [dict(r) for r in rows]

    def add_user(self, username, name, password, role):
        username = str(username).strip().lower()
        name = str(name).strip()
        if not USER_PATTERN.fullmatch(username): raise ValueError('Usuario: 3-40 caracteres, letras, números, puntos o guiones.')
        if not name or len(name) > 120: raise ValueError('Nombre no válido (máximo 120 caracteres).')
        if len(password) < 12 or len(password) > 128: raise ValueError('Contraseña: mínimo 12 caracteres.')
        if role not in ROLES: raise ValueError('Rol no permitido.')
        id_ = uuid.uuid4().hex
        with self.lock:
            try:
                with self.connect() as c:
                    c.execute('INSERT INTO users VALUES(?,?,?,?,?,?,?)',
                              (id_, username, name, password_hash(password), role, 1, utc_now()))
            except sqlite3.IntegrityError:
                raise ValueError('Ese nombre de usuario ya está registrado.')
        return id_

    def modify_user(self, user_id, changes, actor_id):
        with self.lock:
            with self.connect() as c:
                user = c.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
                if not user: raise ValueError('No existe ese usuario.')
                name = str(changes.get('name', user['name'])).strip()
                role = str(changes.get('role', user['role']))
                active = int(bool(changes.get('active', user['active'])))
                password = changes.get('password')
                if not name or len(name) > 120: raise ValueError('Nombre no válido.')
                if role not in ROLES: raise ValueError('Rol no válido.')
                if actor_id == user_id and (role != 'administrador' or not active):
                    raise ValueError('No puedes desactivar tu propia cuenta de administrador.')
                if user['role'] == 'administrador' and (role != 'administrador' or not active):
                    n = c.execute("SELECT COUNT(*) as n FROM users WHERE role='administrador' AND active=1").fetchone()['n']
                    if n <= 1: raise ValueError('Debe permanecer al menos un administrador activo.')
                pw_hash = user['password_hash']
                if password is not None and password != '':
                    if len(str(password)) < 12 or len(str(password)) > 128:
                        raise ValueError('Contraseña: mínimo 12 caracteres.')
                    pw_hash = password_hash(password)
                c.execute('UPDATE users SET name=?,role=?,active=?,password_hash=? WHERE id=?',
                          (name, role, active, pw_hash, user_id))
                if not active or pw_hash != user['password_hash'] or role != user['role']:
                    c.execute('DELETE FROM sessions WHERE user_id=?', (user_id,))

    def revision(self):
        with self.connect() as c:
            row = c.execute('SELECT COALESCE(MAX(seq),0) AS n FROM audit').fetchone()
        return row['n']

    def import_legacy_zip(self, zip_blob, actor):
        """Importa respaldo anterior preservando SIEMPRE las cuentas y sesiones.

        Se reemplazan colecciones de inventario. Archivo ZIP generado por las versiones 2.x.
        """
        if len(zip_blob) > 120 * 1024 * 1024:
            raise ValueError('Respaldo demasiado grande (máximo 120 MB).')
        try:
            z = zipfile.ZipFile(io.BytesIO(zip_blob))
        except (zipfile.BadZipFile, ValueError):
            raise ValueError('Archivo ZIP no válido.')
        with z:
            members = z.infolist()
            if len(members) > 4000 or sum(x.file_size for x in members) > 250 * 1024 * 1024:
                raise ValueError('El respaldo tiene demasiados archivos o excede los límites.')
            if 'inventario.sqlite3' not in z.namelist():
                raise ValueError('Este ZIP no contiene inventario.sqlite3.')
            raw_sqlite = z.read('inventario.sqlite3')
            if not raw_sqlite.startswith(b'SQLite format 3\0') or len(raw_sqlite) > 75 * 1024 * 1024:
                raise ValueError('Base de datos de respaldo no válida.')
            temp = self.data_folder / ('import_' + secrets.token_hex(12) + '.sqlite3')
            try:
                temp.write_bytes(raw_sqlite)
                with sqlite3.connect(f'file:{temp}?mode=ro&immutable=1', uri=True) as old:
                    if old.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                        raise ValueError('La base de datos de origen está dañada.')
                    names = {x[0] for x in old.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                    if 'docs' not in names: raise ValueError('El respaldo no contiene registros de inventario.')
                    records = old.execute("SELECT collection,id,data,updated FROM docs WHERE collection IN ('areas','empleados','bienes','hospital','personas')").fetchall()
                    history = old.execute('SELECT date,action,collection,document_id,details FROM audit ORDER BY seq').fetchall() if 'audit' in names else []
                if len(records) > 50000 or len(history) > 100000:
                    raise ValueError('Demasiados bienes o movimientos en el respaldo.')
                parsed = []
                for col, id_, data, updated in records:
                    obj = json.loads(data)
                    if not isinstance(obj, dict) or len(data) > 400_000 or len(id_) > 100:
                        raise ValueError('Hay un registro no válido en el respaldo.')
                    parsed.append((col, id_, data, updated or utc_now()))
                photos = []
                for entry in members:
                    if entry.filename.startswith('imagenes/') and not entry.is_dir():
                        filename = Path(entry.filename).name
                        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,100}', filename) or entry.file_size > 8 * 1024 * 1024:
                            raise ValueError('Imagen no válida en el respaldo.')
                        photos.append((filename, z.read(entry)))
                # Se escribe todo en una transacción; los usuarios NO se reemplazan.
                with self.lock:
                    with self.connect() as c:
                        c.execute('DELETE FROM docs')
                        c.executemany('INSERT INTO docs(collection,id,data,updated,version) VALUES(?,?,?,?,1)', parsed)
                        # Conservar los movimientos anteriores distinguiéndolos como históricos importados.
                        c.executemany('INSERT INTO audit(date,action,collection,document_id,details) VALUES(?,?,?,?,?)',
                                      [(date, 'histórico:'+str(action)[:90], col, docid, str(details or '')[:500])
                                       for date,action,col,docid,details in history])
                        c.execute('INSERT INTO audit(date,action,collection,document_id,details) VALUES(?,?,?,?,?)',
                                  (utc_now(), 'importacion', None, actor['id'],
                                   f'{len(parsed)} registros importados por {actor["username"]}'))
                    media = self.data_folder / 'imagenes'
                    media.mkdir(parents=True, exist_ok=True)
                    for filename, image in photos:
                        (media / filename).write_bytes(image)
                return {'registros': len(parsed), 'fotografias': len(photos), 'movimientos': len(history)}
            finally:
                temp.unlink(missing_ok=True)
