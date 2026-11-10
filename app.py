"""NOVA Web — Flask + Socket.IO 서버 (macOS/크로스플랫폼)."""
from __future__ import annotations
import json, logging, os, sys, threading, time, webbrowser
from pathlib import Path
from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit
import checker_engine as engine

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger('nova')

app = Flask(__name__, static_folder='static', template_folder='templates')
app.config['SECRET_KEY'] = os.urandom(24).hex()
socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins='*')

session_store: dict = {}
DATA_DIR = Path.home() / '.nova'
DATA_DIR.mkdir(exist_ok=True)
CACHE_FILE = DATA_DIR / 'license_cache.json'


def _load_cache() -> dict:
    try:
        if CACHE_FILE.exists():
            return json.loads(CACHE_FILE.read_text('utf-8'))
    except Exception:
        pass
    return {}


def _save_cache(data: dict):
    try:
        CACHE_FILE.write_text(json.dumps(data, ensure_ascii=False), 'utf-8')
    except Exception:
        pass


def _get_session() -> engine.CheckerSession | None:
    return session_store.get('checker')


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/license/verify', methods=['POST'])
def api_verify_license():
    body = request.get_json(silent=True) or {}
    key = (body.get('key') or '').strip()
    if not key:
        return jsonify({'valid': False, 'error': '키를 입력하세요'}), 400
    result = engine.verify_license(key)
    if result.get('valid'):
        cache = {
            'key': key,
            'signing_secret': result.get('signing_secret', ''),
            'plan': result.get('plan', ''),
            'expires_at': result.get('expires_at', ''),
            'credits_balance': result.get('credits_balance', 0),
            'max_threads': result.get('max_threads', 10),
        }
        _save_cache(cache)
        session_store['license'] = cache
        return jsonify({'valid': True, 'plan': cache['plan'],
                        'expires_at': cache['expires_at'],
                        'max_threads': cache['max_threads']})
    return jsonify(result), 401


@app.route('/api/license/cached', methods=['GET'])
def api_cached_license():
    if 'license' in session_store:
        c = session_store['license']
        return jsonify({'valid': True, 'plan': c.get('plan', ''),
                        'expires_at': c.get('expires_at', '')})
    c = _load_cache()
    if c.get('key'):
        session_store['license'] = c
        return jsonify({'valid': True, 'plan': c.get('plan', ''),
                        'expires_at': c.get('expires_at', '')})
    return jsonify({'valid': False})


@app.route('/api/combos/load', methods=['POST'])
def api_load_combos():
    lic = session_store.get('license')
    if not lic:
        return jsonify({'error': '라이센스를 먼저 인증하세요'}), 401
    text = ''
    if 'file' in request.files:
        text = request.files['file'].read().decode('utf-8', errors='replace')
    elif request.is_json:
        text = request.get_json(silent=True).get('text', '')
    if not text.strip():
        return jsonify({'error': '콤보 데이터가 비어있습니다'}), 400
    def on_result(entry):
        socketio.emit('check_result', entry)
    def on_progress(stats):
        socketio.emit('progress', stats)
    cs = engine.CheckerSession(
        lic['key'], lic.get('signing_secret', ''),
        on_result=on_result, on_progress=on_progress)
    cs.threads = min(int(lic.get('max_threads', 10)), 50)
    count = cs.load_combos(text)
    session_store['checker'] = cs
    return jsonify({'loaded': count, 'threads': cs.threads})


@app.route('/api/check/start', methods=['POST'])
def api_start_check():
    cs = _get_session()
    if not cs:
        return jsonify({'error': '콤보를 먼저 로드하세요'}), 400
    body = request.get_json(silent=True) or {}
    mode = body.get('mode', 'valorant')
    threads = body.get('threads')
    if mode in ('valorant', 'lol', 'both'):
        cs.mode = mode
    if threads and isinstance(threads, int) and 1 <= threads <= 50:
        cs.threads = threads
    cs.start()
    return jsonify({'status': 'started', 'total': cs.stats['total'],
                    'threads': cs.threads, 'mode': cs.mode})


@app.route('/api/check/stop', methods=['POST'])
def api_stop_check():
    cs = _get_session()
    if cs: cs.stop()
    return jsonify({'status': 'stopped'})


@app.route('/api/check/pause', methods=['POST'])
def api_pause_check():
    cs = _get_session()
    if cs:
        cs.pause()
        return jsonify({'paused': cs.paused})
    return jsonify({'paused': False})


@app.route('/api/check/stats', methods=['GET'])
def api_stats():
    cs = _get_session()
    if not cs:
        return jsonify({'checked': 0, 'total': 0, 'hits': 0, 'bans': 0,
                        'errors': 0, 'invalid': 0, 'twofa': 0, 'free': 0,
                        'running': False, 'paused': False})
    return jsonify({**cs.stats, 'running': cs.running, 'paused': cs.paused})


@app.route('/api/results/<category>', methods=['GET'])
def api_results(category):
    cs = _get_session()
    if not cs or category not in cs.results:
        return jsonify({'items': [], 'text': ''})
    items = cs.results[category]
    text = cs.export_results(category)
    return jsonify({'items': items, 'text': text, 'count': len(items)})


@app.route('/api/results/<category>/export', methods=['GET'])
def api_export(category):
    cs = _get_session()
    if not cs:
        return ('', 204)
    text = cs.export_results(category)
    from flask import Response
    return Response(text, mimetype='text/plain',
                    headers={'Content-Disposition': f'attachment; filename={category}.txt'})


@app.route('/api/settings', methods=['GET', 'POST'])
def api_settings():
    cs = _get_session()
    if request.method == 'POST':
        body = request.get_json(silent=True) or {}
        if cs:
            if 'threads' in body:
                cs.threads = max(1, min(50, int(body['threads'])))
            if 'mode' in body and body['mode'] in ('valorant', 'lol', 'both'):
                cs.mode = body['mode']
        return jsonify({'ok': True})
    return jsonify({
        'threads': cs.threads if cs else 5,
        'mode': cs.mode if cs else 'valorant',
        'max_threads': session_store.get('license', {}).get('max_threads', 10),
    })


@socketio.on('connect')
def on_connect():
    cs = _get_session()
    if cs:
        emit('progress', cs.stats)


def open_browser():
    time.sleep(1.2)
    webbrowser.open('http://127.0.0.1:5000')


def main():
    port = int(os.environ.get('NOVA_PORT', 5000))
    if '--no-browser' not in sys.argv:
        threading.Thread(target=open_browser, daemon=True).start()
    logger.info(f'NOVA Web starting on http://127.0.0.1:{port}')
    socketio.run(app, host='127.0.0.1', port=port, debug=False, use_reloader=False)


if __name__ == '__main__':
    import eventlet
    eventlet.monkey_patch()
    main()
