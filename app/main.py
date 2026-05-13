import os
import time
import logging
import secrets
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, session
from flask_cors import CORS
from neo4j import GraphDatabase
from neo4j.exceptions import ServiceUnavailable, AuthError
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

# Auth config — set HOUND_PASS to enable username/password login
HOUND_USER  = os.environ.get('HOUND_USER',  'admin').strip()
HOUND_PASS  = os.environ.get('HOUND_PASS',  '').strip()
HOUND_TOKEN = os.environ.get('HOUND_TOKEN', '').strip()  # legacy token auth, still supported
SECRET_KEY  = os.environ.get('SECRET_KEY',  secrets.token_hex(32))

app.secret_key = SECRET_KEY

AUTH_REQUIRED = bool(HOUND_PASS or HOUND_TOKEN)

# Cypher operations that can never be run via the query API
_BLOCKED_OPS = ['DETACH DELETE', 'DROP ']


@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


def _is_authenticated():
    if not AUTH_REQUIRED:
        return True
    # Session cookie login
    if session.get('authenticated'):
        return True
    # Legacy token header (backward compat for API clients)
    if HOUND_TOKEN and request.headers.get('X-Hound-Token', '') == HOUND_TOKEN:
        return True
    return False


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not _is_authenticated():
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated


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


# ── Auth routes ───────────────────────────────────────────────────────────────

@app.route('/api/auth/login', methods=['POST'])
def login():
    if not HOUND_PASS:
        return jsonify({'error': 'Password auth not configured'}), 400
    data = request.json or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')
    if username == HOUND_USER and password == HOUND_PASS:
        session['authenticated'] = True
        session.permanent = False
        return jsonify({'success': True, 'username': username})
    return jsonify({'error': 'Invalid credentials'}), 401


@app.route('/api/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True})


# ── Routes ────────────────────────────────────────────────────────────────────

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
            # legacy key — kept for backward compat
            'auth': bool(HOUND_TOKEN),
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
@require_auth
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
@require_auth
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
@require_auth
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
