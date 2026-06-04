import os
import json
import time
import logging
import secrets
import sqlite3
import threading
import tempfile
import uuid
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
# Normalise whitespace before checking so newline/tab variants don't bypass
_WRITE_KEYWORDS = ['SET', 'CREATE', 'MERGE', 'REMOVE', 'DELETE']

# Cypher operations that are always blocked regardless of role.
# NOTE: do NOT block `CALL {` — subqueries are a legitimate read pattern (the
# Containers tree uses CALL { ... UNION ... }). Destructive ops inside a
# subquery are still caught: the query is whitespace-normalized before this
# check, so `CALL { MATCH (n) DETACH DELETE n }` still contains 'DETACH DELETE'.
_BLOCKED_OPS = ['DETACH DELETE', 'DETACHDELETE', 'DROP']


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

    # Normalise whitespace so DETACH\nDELETE and SET\nx variants don't bypass checks
    cypher_norm = ' '.join(cypher.upper().split())

    for op in _BLOCKED_OPS:
        if op in cypher_norm:
            return jsonify({'success': False, 'error': f'Operation not permitted: {op}'}), 403

    # Read-only enforcement for 'user' role — check word boundaries via space padding
    if _current_role() == 'user':
        padded = f' {cypher_norm} '
        for op in _WRITE_KEYWORDS:
            if f' {op} ' in padded or f' {op}\n' in padded:
                return jsonify({'success': False, 'error': 'Read-only access: write operations not permitted'}), 403

    try:
        with get_driver().session() as neo4j_session:
            result = neo4j_session.run(cypher, parameters=params, timeout=60)
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


_JOBS_DIR = '/data/jobs'
os.makedirs(_JOBS_DIR, exist_ok=True)

def _job_path(job_id):
    return os.path.join(_JOBS_DIR, f'{job_id}.json')

def _job_read(job_id):
    try:
        with open(_job_path(job_id)) as f:
            return json.load(f)
    except FileNotFoundError:
        return None

def _job_write(job_id, state):
    with open(_job_path(job_id), 'w') as f:
        json.dump(state, f)

def _job_update(job_id, **kwargs):
    state = _job_read(job_id) or {}
    state.update(kwargs)
    _job_write(job_id, state)


def _run_import_job(job_id, tmp_path):
    _job_update(job_id, status='running')
    try:
        def progress_cb(fname, done, total, nodes, rels):
            _job_update(job_id, current_file=fname, files_done=done,
                        files_total=total, nodes=nodes, relationships=rels)

        imp = BloodHoundImporter(get_driver())
        with open(tmp_path, 'rb') as f:
            result = imp.import_zip(f, progress_cb=progress_cb)
        _job_update(job_id, status='complete', result=result, finished=time.time())
    except Exception as e:
        logger.exception(f"Import job {job_id} failed")
        _job_update(job_id, status='error', error=str(e), finished=time.time())
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass
        # Prune job files older than 1 hour
        cutoff = time.time() - 3600
        for f in os.listdir(_JOBS_DIR):
            p = os.path.join(_JOBS_DIR, f)
            try:
                if os.path.getmtime(p) < cutoff:
                    os.unlink(p)
            except Exception:
                pass


@app.route('/api/upload', methods=['POST'])
@require_operator
def upload():
    f = request.files.get('file')
    if not f:
        return jsonify({'error': 'No file provided'}), 400
    try:
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.upload')
        try:
            f.save(tmp)
        finally:
            tmp.close()
    except Exception as e:
        # Don't leak the partial temp file if saving failed
        try:
            os.unlink(tmp.name)
        except Exception:
            pass
        return jsonify({'error': f'Failed to save upload: {e}'}), 500

    job_id = uuid.uuid4().hex[:12]
    _job_write(job_id, {
        'status': 'pending', 'current_file': None,
        'files_done': 0, 'files_total': 0,
        'nodes': 0, 'relationships': 0,
        'result': None, 'error': None,
        'started': time.time(), 'finished': None,
    })
    threading.Thread(target=_run_import_job, args=(job_id, tmp.name), daemon=True).start()
    return jsonify({'job_id': job_id})


@app.route('/api/upload/status/<job_id>')
@require_auth
def upload_status(job_id):
    job = _job_read(job_id)
    if not job:
        return jsonify({'error': 'Job not found'}), 404
    return jsonify(job)


@app.route('/api/upload/jobs')
@require_auth
def upload_jobs():
    """Return all known import jobs, newest first, for the history view."""
    jobs = []
    try:
        for fname in os.listdir(_JOBS_DIR):
            if not fname.endswith('.json'):
                continue
            job = _job_read(fname[:-5])
            if job:
                job['job_id'] = fname[:-5]
                jobs.append(job)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    jobs.sort(key=lambda j: j.get('started') or 0, reverse=True)
    return jsonify({'jobs': jobs})


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


def _recover_stale_jobs():
    """Mark any non-terminal job as failed on startup. An import runs in a
    daemon thread; a container restart kills it mid-run, leaving the job file
    stuck at 'running'/'pending' forever so the UI polls it indefinitely.
    At boot no import can be in flight yet, so this is safe."""
    try:
        for fname in os.listdir(_JOBS_DIR):
            if not fname.endswith('.json'):
                continue
            job_id = fname[:-5]
            job = _job_read(job_id)
            if job and job.get('status') in ('pending', 'running'):
                job['status'] = 'error'
                job['error'] = 'Import interrupted by server restart'
                job['finished'] = time.time()
                _job_write(job_id, job)
    except Exception as e:
        logger.warning(f"Stale job recovery failed: {e}")
    # Sweep temp upload files orphaned by a crash (no import runs at boot)
    try:
        tmpdir = tempfile.gettempdir()
        for fn in os.listdir(tmpdir):
            if fn.endswith('.upload'):
                try:
                    os.unlink(os.path.join(tmpdir, fn))
                except Exception:
                    pass
    except Exception as e:
        logger.warning(f"Temp file sweep failed: {e}")


def startup():
    if wait_for_neo4j():
        try:
            BloodHoundImporter(get_driver())
            logger.info("Schema and indexes initialized.")
        except Exception as e:
            logger.warning(f"Startup schema init failed: {e}")
    _recover_stale_jobs()


startup()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
