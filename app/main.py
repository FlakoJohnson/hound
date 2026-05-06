import os
import time
import logging
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from neo4j import GraphDatabase
from neo4j.exceptions import ServiceUnavailable, AuthError
from queries import QUERIES
from importer import BloodHoundImporter

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder='static')
app.config['MAX_CONTENT_LENGTH'] = 512 * 1024 * 1024  # 512MB max upload

CORS(app)

# Optional static token auth — set HOUND_TOKEN env var to enable
HOUND_TOKEN = os.environ.get('HOUND_TOKEN', '').strip()

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


def require_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if HOUND_TOKEN:
            if request.headers.get('X-Hound-Token', '') != HOUND_TOKEN:
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


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/api/health')
def health():
    # Intentionally unprotected — used to check connectivity and whether auth is required
    try:
        with get_driver().session() as s:
            s.run("RETURN 1")
        return jsonify({'status': 'ok', 'neo4j': 'connected', 'auth': bool(HOUND_TOKEN)})
    except Exception as e:
        return jsonify({'status': 'error', 'neo4j': str(e)}), 503

@app.route('/api/queries')
@require_token
def get_queries():
    return jsonify(QUERIES)

@app.route('/api/stats')
@require_token
def get_stats():
    try:
        imp = BloodHoundImporter(get_driver())
        return jsonify(imp.get_stats())
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/run', methods=['POST'])
@require_token
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
        with get_driver().session() as session:
            result = session.run(cypher, parameters=params)
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
@require_token
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

@app.route('/api/clear', methods=['POST'])
@require_token
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
