import argparse
import datetime as dt
import json
import os
from pathlib import Path
import signal
import subprocess
import threading
import uuid
from urllib.parse import urlsplit

STOP = threading.Event()
CHILD = None

def stop(signum, frame):
    STOP.set()
    if CHILD is not None and CHILD.poll() is None:
        CHILD.terminate()

def run_once():
    global CHILD
    targets = [x.strip() for x in os.getenv('CARIDDI_TARGETS', '').splitlines() if x.strip()]
    if not targets:
        raise ValueError('CARIDDI_TARGETS fehlt: eine autorisierte http(s)-URL pro Zeile erforderlich')
    for target in targets:
        url = urlsplit(target)
        if url.scheme not in ('http', 'https') or not url.hostname or url.username or url.password:
            raise ValueError('Nur http(s)-URLs ohne Zugangsdaten erlaubt')
    args = json.loads(os.getenv('CARIDDI_ARGS_JSON', '["-c","5","-d","1","-md","2","-t","10","-e","-json"]'))
    if not isinstance(args, list) or not all(isinstance(x, str) for x in args):
        raise ValueError('CARIDDI_ARGS_JSON muss ein JSON-Array aus Strings sein')
    timeout = int(os.getenv('SCAN_TIMEOUT_SECONDS', '1800'))
    if timeout < 1:
        raise ValueError('SCAN_TIMEOUT_SECONDS muss positiv sein')
    folder = Path('/data/runs') / (dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8])
    folder.mkdir(parents=True, mode=0o700)
    started = dt.datetime.now(dt.timezone.utc).isoformat()
    status = {'started_at': started, 'status': 'running'}
    metadata = folder / 'status.json'
    metadata.write_text(json.dumps(status, indent=2))
    print(f'Scan gestartet: {folder.name}', flush=True)
    code = 1
    try:
        with (folder / 'stdout.log').open('w') as stdout, (folder / 'stderr.log').open('w') as stderr:
            CHILD = subprocess.Popen(['cariddi', *args], stdin=subprocess.PIPE, stdout=stdout, stderr=stderr, text=True, cwd=folder)
            try:
                CHILD.communicate(input='\n'.join(targets) + '\n', timeout=timeout)
                code = CHILD.returncode
                status['status'] = 'success' if code == 0 else 'failed'
                if STOP.is_set():
                    status['status'] = 'cancelled'
            except subprocess.TimeoutExpired:
                CHILD.kill()
                CHILD.communicate()
                code = 124
                status['status'] = 'timeout'
    finally:
        CHILD = None
        status.update(exit_code=code, finished_at=dt.datetime.now(dt.timezone.utc).isoformat())
        metadata.write_text(json.dumps(status, indent=2))
    print(f'Scan beendet: {folder.name}, Status={status["status"]}, Exit={code}', flush=True)
    return code

def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description='hAI.cariddi: explizit autorisierte Scans')
    parser.add_argument('--once', action='store_true')
    options = parser.parse_args()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    if options.once:
        return run_once()
    if os.getenv('SCAN_ENABLED', 'false').lower() != 'true':
        print('Idle: SCAN_ENABLED ist nicht true; kein Scan wird gestartet.', flush=True)
        while not STOP.wait(60):
            pass
        return 0
    interval = int(os.getenv('SCAN_INTERVAL_SECONDS', '0'))
    if interval < 0:
        raise ValueError('SCAN_INTERVAL_SECONDS darf nicht negativ sein')
    while not STOP.is_set():
        result = run_once()
        if interval == 0:
            print('Einmallauf beendet; Container bleibt idle.', flush=True)
            while not STOP.wait(60):
                pass
            return result
        if STOP.wait(interval):
            break
    return 0

if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError) as exc:
        print(f'Konfigurations-/Laufzeitfehler: {exc}', flush=True)
        raise SystemExit(2)
