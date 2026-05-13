import os
import time
import logging
import secrets
import sqlite3
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, session
from flask_cors import CORS
from neo4j import GraphDatabase
from neo4j.exceptions import ServiceUnavailable, AuthError
from werkzeug.security import generate_password_hash, check_password_hash
from queries import QUERIES
from importer import BloodHoundImporter

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder='static')
app.config['MAX_CONTENT_LENGTH'] = 512 * 1024 * 1024  # 512MB max upload
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.json.sort_keys = False

CORS(app, supports_credentials=True)

HOUND_USER  = os.environ.get('HOUND_USER',  'admin').strip()
HOUND_PASS  = os.environ.get('HOUND_PASS',  '').strip()
HOUND_TOKEN = os.environ.get('HOUND_TOKEN', '').strip()  # legacy token auth, still supported
SECRET_KEY  = os.environ.get('SECRET_KEY',  '').strip() or secrets.token_hex(32)

app.secret_key = SECRET_KEY

# Roles in ascending privilege order
VALID_ROLES = ('user', 'operator', 'admin')

# Cypher write keywords blocked for read-only 'user' role
_WRITE_KEYWORDS = ['SET ', 'CREATE ', 'MERGE ', 'REMOVE ', 'DELETE ']

# Cypher operations that are always blocked regardless of role
_BLOCKED_OPS = ['DETACH DELETE', 'DROP ']


@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


# ── User store ────────────────────────────────────────────────────────────────

DB_PATH = '/data/users.db'


class UserStore:
    def __init__(self, path):
        self.path = path
        self._init()

    def _conn(self):
        c = sqlite3.connect(self.path)
        c.row_factory = sqlite3.Row
        return c

    def _init(self):
        with self._conn() as c:
            c.execute('''CREATE TABLE IF NOT EXISTS users (
                id            TEXT PRIMARY KEY,
                username      TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role          TEXT NOT NULL DEFAULT 'operator',
                disabled      INTEGER NOT NULL DEFAULT 0,
                created_at    INTEGER NOT NULL,
                last_login_at INTEGER
            )''')
            # Migrate old 'user' role (pre-rename) to 'operator'
            c.execute("UPDATE users SET role='operator' WHERE role='user'")

    def count(self):
        with self._conn() as c:
            return c.execute('SELECT COUNT(*) FROM users').fetchone()[0]

    def create(self, username, password, role='operator'):
        uid = secrets.token_hex(16)
        with self._conn() as c:
            c.execute(
                'INSERT INTO users (id,username,password_hash,role,created_at) VALUES (?,?,?,?,?)',
                (uid, username, generate_password_hash(password), role, int(time.time()))
            )
        return uid

    def get_by_username(self, username):
        with self._conn() as c:
            r = c.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
            return dict(r) if r else None

    def get_by_id(self, uid):
        with self._conn() as c:
            r = c.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
            return dict(r) if r else None

    def list_all(self):
        with self._conn() as c:
            return [dict(r) for r in c.execute(
                'SELECT id,username,role,disabled,created_at,last_login_at FROM users ORDER BY created_at'
            )]

    def touch_login(self, uid):
        with self._conn() as c:
            c.execute('UPDATE users SET last_login_at=? WHERE id=?', (int(time.time()), uid))

    def update(self, uid, **kw):
        allowed = {'disabled', 'role'}
        fields = {k: v for k, v in kw.items() if k in allowed}
        if not fields:
            return
        cols = ', '.join(f'{k}=?' for k in fields)
        with self._conn() as c:
            c.execute(f'UPDATE users SET {cols} WHERE id=?', (*fields.values(), uid))

    def set_password(self, uid, password):
        with self._conn() as c:
            c.execute('UPDATE users SET password_hash=? WHERE id=?',
                      (generate_password_hash(password), uid))

    def delete(self, uid):
        with self._conn() as c:
            c.execute('DELETE FROM users WHERE id=?', (uid,))


user_store = UserStore(DB_PATH)

# Bootstrap admin from env vars on first run (no users in DB yet)
if HOUND_PASS and user_store.count() == 0:
    user_store.create(HOUND_USER, HOUND_PASS, role='admin')
    logger.info(f"Bootstrapped admin '{HOUND_USER}' from HOUND_PASS")

AUTH_REQUIRED = bool(user_store.count() > 0 or HOUND_TOKEN)


# ── Auth helpers ───────────────────────────────────────────────────────────────

def _current_role():
    """Return the effective role for the current request."""
    if not AUTH_REQUIRED:
        return 'admin'
    return session.get('role', '')


def _is_authenticated():
    if not AUTH_REQUIRED:
        return True
    if session.get('user_id'):
        return True
    if HOUND_TOKEN and request.headers.get('X-Hound-Token', '') == HOUND_TOKEN:
        return True
    return False


def require_auth(f):
    """Any authenticated user."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not _is_authenticated():
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated


def require_operator(f):
    """Operator or admin (not read-only user)."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not _is_authenticated():
            return jsonify({'error': 'Unauthorized'}), 401
        role = _current_role()
        if AUTH_REQUIRED and role not in ('operator', 'admin'):
            return jsonify({'error': 'Forbidden: operator role required'}), 403
        return f(*args, **kwargs)
    return decorated


def require_admin(f):
    """Admin only."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not _is_authenticated():
            return jsonify({'error': 'Unauthorized'}), 401
        if AUTH_REQUIRED and _current_role() != 'admin':
            return jsonify({'error': 'Forbidden: admin role required'}), 403
        return f(*args, **kwargs)
    return decorated


# ── Neo4j ──────────────────────────────────────────────────────────────────────

NEO4J_URI  = os.environ.get('NEO4J_URI',  'bolt://neo4j:7687')
NEO4J_USER = os.environ.get('NEO4J_USER', 'neo4j')
NEO4J_PASS = os.environ.get('NEO4J_PASS', 'bloodhound')

driver = None


def get_driver():
    global driver
    if driver is None:
        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
    return driver


def wait_for_neo4j(retries=30, delay=3):
    for i in range(retries):
        try:
            with get_driver().session() as s:
                s.run("RETURN 1")
            logger.info("Neo4j connected.")
            return True
        except (ServiceUnavailable, AuthError, Exception) as e:
            logger.warning(f"Neo4j not ready ({i+1}/{retries}): {e}")
            time.sleep(delay)
    return False


# ── Auth routes ────────────────────────────────────────────────────────────────

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400

    user = user_store.get_by_username(username)
    if not user or not check_password_hash(user['password_hash'], password):
        return jsonify({'error': 'Invalid credentials'}), 401
    if user['disabled']:
        return jsonify({'error': 'Account disabled'}), 401

    user_store.touch_login(user['id'])
    session['user_id']  = user['id']
    session['username'] = user['username']
    session['role']     = user['role']
    session.permanent   = False
    return jsonify({'success': True, 'id': user['id'], 'username': user['username'], 'role': user['role']})


@app.route('/api/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True})


@app.route('/api/auth/whoami')
@require_auth
def whoami():
    if not AUTH_REQUIRED:
        return jsonify({'id': '', 'username': 'anonymous', 'role': 'admin'})
    uid = session.get('user_id')
    if uid:
        user = user_store.get_by_id(uid)
        if user:
            return jsonify({'id': user['id'], 'username': user['username'], 'role': user['role']})
    # Legacy token auth — treat as admin with no user record
    return jsonify({'id': '', 'username': 'api', 'role': 'admin'})


# ── User management routes ─────────────────────────────────────────────────────

@app.route('/api/users', methods=['GET'])
@require_admin
def list_users():
    return jsonify({'users': user_store.list_all()})


@app.route('/api/users', methods=['POST'])
@require_admin
def create_user():
    data = request.json or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')
    role     = data.get('role', 'operator')
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    if role not in VALID_ROLES:
        return jsonify({'error': f'Invalid role (must be one of: {", ".join(VALID_ROLES)})'}), 400
    try:
        uid = user_store.create(username, password, role)
        return jsonify({'success': True, 'id': uid})
    except Exception as e:
        if 'UNIQUE' in str(e):
            return jsonify({'error': 'Username already exists'}), 409
        return jsonify({'error': str(e)}), 500


@app.route('/api/users/<uid>', methods=['PUT'])
@require_admin
def update_user(uid):
    data = request.json or {}
    kw = {}
    if 'disabled' in data:
        kw['disabled'] = int(bool(data['disabled']))
    if 'role' in data:
        if data['role'] not in VALID_ROLES:
            return jsonify({'error': 'Invalid role'}), 400
        kw['role'] = data['role']
    user_store.update(uid, **kw)
    return jsonify({'success': True})


@app.route('/api/users/<uid>/password', methods=['POST'])
@require_auth
def change_password(uid):
    if _current_role() != 'admin' and session.get('user_id') != uid:
        return jsonify({'error': 'Forbidden'}), 403
    data = request.json or {}
    new_password = data.get('password', '')
    if not new_password:
        return jsonify({'error': 'Password required'}), 400
    user_store.set_password(uid, new_password)
    return jsonify({'success': True})


@app.route('/api/users/<uid>', methods=['DELETE'])
@require_admin
def delete_user(uid):
    if uid == session.get('user_id'):
        return jsonify({'error': 'Cannot delete your own account'}), 400
    user_store.delete(uid)
    return jsonify({'success': True})


# ── App routes ─────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')


@app.route('/api/health')
def health():
    try:
        with get_driver().session() as s:
            s.run("RETURN 1")
        return jsonify({
            'status': 'ok',
            'neo4j': 'connected',
            'auth_required': AUTH_REQUIRED,
            'authenticated': _is_authenticated(),
            'auth': bool(HOUND_TOKEN),  # legacy key — backward compat
        })
    except Exception as e:
        return jsonify({'status': 'error', 'neo4j': str(e), 'auth_required': AUTH_REQUIRED}), 503


@app.route('/api/queries')
@require_auth
def get_queries():
    return jsonify(QUERIES)


@app.route('/api/stats')
@require_auth
def get_stats():
    try:
        imp = BloodHoundImporter(get_driver())
        return jsonify(imp.get_stats())
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/run', methods=['POST'])
@require_auth
def run_query():
    data = request.json or {}
    cypher = data.get('cypher', '').strip()
    params = data.get('params', {})
    if not cypher:
        return jsonify({'success': False, 'error': 'No query provided'}), 400

    if not isinstance(params, dict):
        params = {}

    cypher_upper = cypher.upper()

    for op in _BLOCKED_OPS:
        if op in cypher_upper:
            return jsonify({'success': False, 'error': f'Operation not permitted: {op}'}), 403

    # Read-only enforcement for 'user' role
    if _current_role() == 'user':
        for op in _WRITE_KEYWORDS:
            if op in cypher_upper:
                return jsonify({'success': False, 'error': 'Read-only access: write operations not permitted'}), 403

    try:
        with get_driver().session() as neo4j_session:
            result = neo4j_session.run(cypher, parameters=params)
            keys = list(result.keys())
            records = []
            for record in result:
                row = {}
                for k in keys:
                    v = record[k]
                    if hasattr(v, '__class__') and v.__class__.__name__ in ('Node', 'Relationship', 'Path'):
                        row[k] = str(v)
                    elif isinstance(v, list):
                        row[k] = [str(i) if not isinstance(i, (str, int, float, bool, type(None))) else i for i in v]
                    else:
                        row[k] = v
                records.append(row)
            return jsonify({'success': True, 'keys': keys, 'data': records, 'count': len(records)})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 200


@app.route('/api/upload', methods=['POST'])
@require_operator
def upload():
    f = request.files.get('file')
    if not f:
        return jsonify({'error': 'No file provided'}), 400
    try:
        imp = BloodHoundImporter(get_driver())
        result = imp.import_zip(f)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/notes', methods=['POST'])
@require_operator
def save_note():
    data = request.json or {}
    objectid = data.get('objectid', '').strip()
    text = data.get('text', '')
    if not objectid:
        return jsonify({'error': 'No objectid provided'}), 400
    try:
        with get_driver().session() as neo4j_session:
            neo4j_session.run(
                'MATCH (n) WHERE n.objectid = $oid SET n.hound_notes = $text',
                oid=objectid, text=text
            )
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/clear', methods=['POST'])
@require_operator
def clear_db():
    try:
        imp = BloodHoundImporter(get_driver())
        imp.clear_database()
        return jsonify({'success': True, 'message': 'Database cleared'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    wait_for_neo4j()
    app.run(host='0.0.0.0', port=5000, debug=False)
