import datetime as dt
import hmac
import html
import http.server
import ipaddress
import json
import os
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

NL = chr(10)
DATA = Path(os.getenv('DATA_DIR', '/data'))
RUNS = DATA / 'runs'
PASSWORD = os.getenv('ADMIN_PASSWORD', '')
ALLOWED = [x.strip().lower() for x in os.getenv('ALLOWED_HOSTS', '').split(',') if x.strip()]
ALLOW_PRIVATE = os.getenv('ALLOW_PRIVATE_TARGETS', 'false').lower() == 'true'
COOKIE_SECURE = os.getenv('COOKIE_SECURE', 'false').lower() == 'true'
TIMEOUT = max(60, min(int(os.getenv('SCAN_TIMEOUT_SECONDS', '1800')), 86400))
RUN_ID = re.compile(r'^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$')
ROUTE = re.compile(r'^/run/([^/]+)(/(stdout|stderr)[.]log)?$')
LOCK = threading.Lock()
CURRENT = {'id': None, 'proc': None, 'stop': False}
SESSIONS = {}
FAILS = {}
esc = html.escape
CSP = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
CSS = 'body{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;margin:0}main{max-width:900px;margin:auto;padding:1rem}header{display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem}.card{background:#1e293b;border-radius:10px;padding:1rem;margin-bottom:1rem}label{display:block;margin:.5rem 0 .2rem}input,select,textarea{width:100%;box-sizing:border-box;padding:.5rem;border-radius:6px;border:1px solid #475569;background:#0f172a;color:#e2e8f0}.chk{display:flex;gap:.5rem;align-items:center}.chk input{width:auto}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:.5rem}button{margin-top:1rem;padding:.6rem 1.2rem;border:0;border-radius:6px;background:#2563eb;color:#fff;font-size:1rem}button.danger{background:#dc2626}button.link{background:none;margin:0;color:#93c5fd}a{color:#93c5fd}pre{background:#0f172a;padding:.6rem;border-radius:6px;overflow:auto;max-height:22rem;white-space:pre-wrap;word-break:break-all}.err{background:#7f1d1d;padding:.6rem;border-radius:6px}.warn{background:#78350f;padding:.6rem;border-radius:6px}table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:.4rem;border-bottom:1px solid #334155}'


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')


def val(form, key):
    return form.get(key, [''])[0]


def clamp(form, key, lo, hi, default):
    try:
        v = int(val(form, key))
    except ValueError:
        return default
    return max(lo, min(hi, v))


def build_args(form):
    args = ['-c', str(clamp(form, 'c', 1, 20, 5)), '-d', str(clamp(form, 'd', 0, 30, 1)), '-md', str(clamp(form, 'md', 1, 5, 2)), '-t', str(clamp(form, 't', 1, 60, 10)), '-json']
    for key, flag in (('e', '-e'), ('s', '-s'), ('err', '-err'), ('info', '-info'), ('rua', '-rua'), ('intensive', '-intensive')):
        if val(form, key) == '1':
            args.append(flag)
    ext = clamp(form, 'ext', 0, 7, 0)
    if ext:
        args += ['-ext', str(ext)]
    return args


def validate_targets(text):
    lines = [x.strip() for x in text.splitlines() if x.strip()]
    if not lines or len(lines) > 50:
        raise ValueError('1 bis 50 Ziele, eine URL pro Zeile')
    out = []
    for line in lines:
        u = urlsplit(line)
        try:
            port = u.port
        except ValueError:
            raise ValueError('Ungueltiger Port: ' + line)
        host = (u.hostname or '').lower()
        if u.scheme not in ('http', 'https') or not host or u.username or u.password:
            raise ValueError('Nur http(s)-URLs ohne Zugangsdaten: ' + line)
        if ALLOWED and not any(host == a or host.endswith('.' + a) for a in ALLOWED):
            raise ValueError('Host nicht in ALLOWED_HOSTS: ' + host)
        try:
            infos = socket.getaddrinfo(host, port or (443 if u.scheme == 'https' else 80), type=socket.SOCK_STREAM)
        except OSError:
            raise ValueError('Host nicht aufloesbar: ' + host)
        for info in infos:
            ip = ipaddress.ip_address(info[4][0].split('%')[0])
            if not ALLOW_PRIVATE and not ip.is_global:
                raise ValueError('Nicht-oeffentliche Adresse blockiert (siehe ALLOW_PRIVATE_TARGETS): ' + host)
        out.append(line)
    return out


def meta_path(rid):
    return RUNS / rid / 'meta.json'


def load_meta(rid):
    try:
        return json.loads(meta_path(rid).read_text())
    except (OSError, ValueError):
        return None


def save_meta(rid, meta):
    tmp = meta_path(rid).with_suffix('.tmp')
    tmp.write_text(json.dumps(meta, indent=2))
    tmp.replace(meta_path(rid))


def list_runs(limit=30):
    if not RUNS.exists():
        return []
    ids = sorted((p.name for p in RUNS.iterdir() if RUN_ID.match(p.name)), reverse=True)[:limit]
    return [m for m in (load_meta(i) for i in ids) if m]


def recover():
    RUNS.mkdir(parents=True, exist_ok=True)
    for p in RUNS.iterdir():
        if RUN_ID.match(p.name):
            m = load_meta(p.name)
            if m and m.get('status') == 'running':
                m['status'] = 'interrupted'
                m['finished_at'] = now()
                save_meta(p.name, m)


def run_job(rid, targets, args):
    d = RUNS / rid
    meta = load_meta(rid) or {'id': rid}
    code, status = 1, 'failed'
    try:
        with open(d / 'stdout.log', 'wb') as so, open(d / 'stderr.log', 'wb') as se:
            p = subprocess.Popen(['cariddi'] + args, stdin=subprocess.PIPE, stdout=so, stderr=se, cwd=d)
            with LOCK:
                CURRENT['proc'] = p
                early_stop = CURRENT['stop']
            if early_stop:
                p.terminate()
            try:
                p.communicate((NL.join(targets) + NL).encode(), timeout=TIMEOUT)
                code = p.returncode
                status = 'success' if code == 0 else 'failed'
            except subprocess.TimeoutExpired:
                p.kill()
                p.communicate()
                code, status = 124, 'timeout'
            with LOCK:
                if CURRENT['stop']:
                    status = 'cancelled'
    except Exception as exc:
        status = 'error'
        meta['error'] = str(exc)
    finally:
        meta.update(status=status, exit_code=code, finished_at=now())
        save_meta(rid, meta)
        with LOCK:
            CURRENT.update(id=None, proc=None, stop=False)


def start_job(form):
    targets = validate_targets(val(form, 'targets'))
    if val(form, 'authorized') != '1':
        raise ValueError('Die Berechtigung fuer alle Ziele muss bestaetigt werden')
    args = build_args(form)
    if '-intensive' in args and not ALLOWED:
        raise ValueError('-intensive ist nur mit gesetzter ALLOWED_HOSTS-Liste erlaubt')
    rid = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8]
    with LOCK:
        if CURRENT['id']:
            raise ValueError('Es laeuft bereits ein Scan')
        CURRENT.update(id=rid, proc=None, stop=False)
    try:
        (RUNS / rid).mkdir(parents=True, mode=0o700)
        save_meta(rid, {'id': rid, 'created': now(), 'targets': targets, 'args': args, 'status': 'running'})
        threading.Thread(target=run_job, args=(rid, targets, args), daemon=True).start()
    except Exception:
        with LOCK:
            CURRENT.update(id=None, proc=None, stop=False)
        raise
    return rid


def stop_job():
    with LOCK:
        CURRENT['stop'] = True
        p = CURRENT['proc']
    if p and p.poll() is None:
        p.terminate()
        threading.Timer(10, lambda: p.poll() is None and p.kill()).start()


def tail(path, lines=150, size=65536):
    try:
        with open(path, 'rb') as f:
            f.seek(0, 2)
            end = f.tell()
            f.seek(max(0, end - size))
            data = f.read()
    except OSError:
        return ''
    return NL.join(data.decode('utf-8', 'replace').split(NL)[-lines:])


def page(title, body, refresh=0):
    meta = '<meta http-equiv=refresh content=%d>' % refresh if refresh else ''
    return '<!doctype html><html lang=de><head><meta charset=utf-8>' + "<meta name=viewport content='width=device-width,initial-scale=1'>" + meta + '<title>' + esc(title) + '</title><style>' + CSS + '</style></head><body><main>' + body + '</main></body></html>'


def top(csrf):
    return '<header><b>hAI.cariddi</b><form method=post action=/logout><input type=hidden name=csrf value=' + csrf + '><button class=link>Abmelden</button></form></header>'


def login_page(err=''):
    b = '<h1>hAI.cariddi</h1>'
    if err:
        b += '<p class=err>' + esc(err) + '</p>'
    b += '<form method=post action=/login class=card><label>Passwort</label><input type=password name=password autofocus required><button>Anmelden</button></form>'
    return page('Login', b)


def num(name, label, default, lo, hi):
    return '<label>' + label + '<input type=number name=' + name + ' value=' + str(default) + ' min=' + str(lo) + ' max=' + str(hi) + '></label>'


def chk(name, label, checked=False):
    return '<label class=chk><input type=checkbox name=' + name + ' value=1' + (' checked' if checked else '') + '> ' + label + '</label>'


def dashboard(csrf, err='', prefill=''):
    running = CURRENT['id']
    b = top(csrf)
    if err:
        b += '<p class=err>' + esc(err) + '</p>'
    if running:
        b += '<p class=warn>Scan laeuft: <a href=/run/' + running + '>' + running + '</a></p>'
    b += '<form method=post action=/start class=card><h2>Neuer Scan</h2><input type=hidden name=csrf value=' + csrf + '>'
    b += '<label>Ziele (eine http(s)-URL pro Zeile, max. 50)</label><textarea name=targets rows=5 required>' + esc(prefill) + '</textarea>'
    b += '<div class=grid>' + num('c', 'Parallelitaet', 5, 1, 20) + num('d', 'Delay (s)', 1, 0, 30) + num('md', 'Max. Tiefe', 2, 1, 5) + num('t', 'Timeout (s)', 10, 1, 60) + '</div>'
    b += '<label>Dateiendungen (Stufe 1 = interessant, 7 = unwichtig)<select name=ext><option value=0>aus</option>' + ''.join('<option value=%d>%d</option>' % (i, i) for i in range(1, 8)) + '</select></label>'
    b += chk('e', 'Endpoints suchen (-e)', True) + chk('s', 'Secrets suchen (-s)') + chk('err', 'Fehlermeldungen suchen (-err)') + chk('info', 'Infos suchen (-info)') + chk('rua', 'Zufaelliger User-Agent (-rua)')
    if ALLOWED:
        b += chk('intensive', 'Intensiv: Subdomains mitcrawlen (-intensive)')
    b += '<hr>' + chk('authorized', 'Ich bestaetige, dass ich zum Testen aller genannten Ziele berechtigt bin.')
    b += '<button' + (' disabled' if running else '') + '>Scan starten</button></form>'
    b += '<div class=card><h2>Letzte Laeufe</h2><table><tr><th>Start (UTC)</th><th>Status</th><th>Ziele</th></tr>'
    for m in list_runs():
        b += '<tr><td><a href=/run/' + esc(m['id']) + '>' + esc(m.get('created', m['id'])) + '</a></td><td>' + esc(m.get('status', '?')) + '</td><td>' + str(len(m.get('targets', []))) + '</td></tr>'
    b += '</table></div>'
    return page('hAI.cariddi', b, 10 if running else 0)


def run_page(csrf, rid):
    m = load_meta(rid)
    if not m:
        return None
    d = RUNS / rid
    st = m.get('status', '?')
    b = top(csrf) + '<p><a href=/>Zurueck</a></p><div class=card><h2>Lauf ' + esc(rid) + '</h2>'
    b += '<p>Status: <b>' + esc(st) + '</b> | Exit: ' + esc(str(m.get('exit_code', '-'))) + '</p>'
    b += '<p>Start: ' + esc(m.get('created', '')) + ' | Ende: ' + esc(m.get('finished_at', '-')) + '</p>'
    b += '<p>Ziele:</p><pre>' + esc(NL.join(m.get('targets', []))) + '</pre><p>Argumente: <code>' + esc(' '.join(m.get('args', []))) + '</code></p>'
    if m.get('error'):
        b += '<p class=err>' + esc(m['error']) + '</p>'
    if st == 'running':
        b += '<form method=post action=/stop><input type=hidden name=csrf value=' + csrf + '><button class=danger>Scan stoppen</button></form>'
    else:
        b += '<form method=post action=/delete/' + rid + '><input type=hidden name=csrf value=' + csrf + '><button class=danger>Lauf loeschen</button></form>'
    b += '</div><div class=card><h3>stdout (Ende)</h3><a href=/run/' + rid + '/stdout.log>Download</a><pre>' + esc(tail(d / 'stdout.log')) + '</pre>'
    b += '<h3>stderr (Ende)</h3><a href=/run/' + rid + '/stderr.log>Download</a><pre>' + esc(tail(d / 'stderr.log')) + '</pre></div>'
    return page('Lauf ' + rid, b, 5 if st == 'running' else 0)


class H(http.server.BaseHTTPRequestHandler):
    server_version = 'hAI'
    sys_version = ''

    def log_message(self, fmt, *args):
        sys.stdout.write(self.client_address[0] + ' ' + (fmt % args) + NL)
        sys.stdout.flush()

    def send(self, code, body, ctype='text/html; charset=utf-8', extra=()):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Content-Security-Policy', CSP)
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, loc, extra=()):
        self.send(303, '', extra=(('Location', loc),) + tuple(extra))

    def session(self):
        for part in self.headers.get('Cookie', '').split(';'):
            k, _, v = part.strip().partition('=')
            if k == 'sid':
                s = SESSIONS.get(v)
                if s and s['exp'] > time.time():
                    return v, s
        return None, None

    def form(self):
        n = int(self.headers.get('Content-Length', '0') or 0)
        if n < 0 or n > 65536:
            raise ValueError('Anfrage zu gross')
        return parse_qs(self.rfile.read(n).decode('utf-8', 'replace'), keep_blank_values=True)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == '/healthz':
            return self.send(200, 'ok', 'text/plain')
        if path == '/login':
            return self.send(200, login_page())
        sid, s = self.session()
        if not s:
            return self.redirect('/login')
        if path == '/':
            return self.send(200, dashboard(s['csrf']))
        m = ROUTE.match(path)
        if m and RUN_ID.match(m.group(1)):
            rid, fname = m.group(1), m.group(3)
            if fname:
                f = RUNS / rid / (fname + '.log')
                if not f.is_file():
                    return self.send(404, 'nicht gefunden', 'text/plain')
                with open(f, 'rb') as fh:
                    data = fh.read(20000000)
                return self.send(200, data, 'text/plain; charset=utf-8', (('Content-Disposition', 'attachment; filename=cariddi-' + rid + '-' + fname + '.log'),))
            body = run_page(s['csrf'], rid)
            if body:
                return self.send(200, body)
        self.send(404, 'nicht gefunden', 'text/plain')

    def do_POST(self):
        path = urlsplit(self.path).path
        try:
            f = self.form()
        except ValueError as exc:
            return self.send(400, str(exc), 'text/plain')
        if path == '/login':
            ip = self.client_address[0]
            fails = [t for t in FAILS.get(ip, []) if t > time.time() - 300]
            if len(fails) >= 5:
                return self.send(429, login_page('Zu viele Versuche. Bitte spaeter erneut versuchen.'))
            if hmac.compare_digest(val(f, 'password').encode(), PASSWORD.encode()):
                FAILS.pop(ip, None)
                for k in [k for k, v in SESSIONS.items() if v['exp'] < time.time()]:
                    SESSIONS.pop(k, None)
                sid = secrets.token_urlsafe(32)
                SESSIONS[sid] = {'csrf': secrets.token_urlsafe(24), 'exp': time.time() + 28800}
                cookie = 'sid=' + sid + '; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800' + ('; Secure' if COOKIE_SECURE else '')
                return self.redirect('/', (('Set-Cookie', cookie),))
            fails.append(time.time())
            FAILS[ip] = fails
            time.sleep(1)
            return self.send(401, login_page('Falsches Passwort.'))
        sid, s = self.session()
        if not s:
            return self.redirect('/login')
        if not hmac.compare_digest(val(f, 'csrf').encode(), s['csrf'].encode()):
            return self.send(403, 'CSRF-Pruefung fehlgeschlagen', 'text/plain')
        if path == '/logout':
            SESSIONS.pop(sid, None)
            return self.redirect('/login', (('Set-Cookie', 'sid=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict'),))
        if path == '/start':
            try:
                return self.redirect('/run/' + start_job(f))
            except (ValueError, OSError) as exc:
                return self.send(400, dashboard(s['csrf'], str(exc), val(f, 'targets')))
        if path == '/stop':
            stop_job()
            return self.redirect('/')
        if path.startswith('/delete/'):
            rid = path[len('/delete/'):]
            if RUN_ID.match(rid) and CURRENT['id'] != rid and (RUNS / rid).is_dir():
                shutil.rmtree(RUNS / rid, ignore_errors=True)
            return self.redirect('/')
        self.send(404, 'nicht gefunden', 'text/plain')


def main():
    if '--selftest' in sys.argv:
        args = build_args({})
        assert args[:2] == ['-c', '5'] and '-json' in args
        assert RUN_ID.match('20260101T000000Z-0123abcd')
        print('selftest ok')
        return 0
    if len(PASSWORD) < 12:
        print('ADMIN_PASSWORD fehlt oder ist kuerzer als 12 Zeichen', flush=True)
        return 2
    recover()
    srv = http.server.ThreadingHTTPServer(('0.0.0.0', int(os.getenv('PORT', '8080'))), H)

    def term(signum, frame):
        stop_job()
        threading.Thread(target=srv.shutdown).start()

    signal.signal(signal.SIGTERM, term)
    signal.signal(signal.SIGINT, term)
    print('hAI.cariddi Web-UI auf Port 8080', flush=True)
    srv.serve_forever()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
