"""Generic Module 3 transport plus an explicitly simulated demonstration fixture."""
import json
from contextlib import closing
from pathlib import Path
import sqlite3
from urllib.parse import urlsplit
from uuid import uuid4
import httpx
from .domain import InputError, Scan, canonical, digest, strict_json, timestamp, utcnow


class HTTPConnector:
    def __init__(self, base_url, token, *, client=None):
        url = urlsplit(base_url)
        if url.username or url.password or url.query or url.fragment or not url.hostname:
            raise ValueError('Connector URL must not contain credentials, queries or fragments')
        if url.scheme != 'https' and not (url.scheme == 'http' and url.hostname in ('localhost', '127.0.0.1', '::1')):
            raise ValueError('Use HTTPS for remote connectors; HTTP is limited to loopback')
        if not token or any(ord(c) < 33 or ord(c) > 126 for c in token):
            raise ValueError('A valid connector service token is required')
        self.base_url, self.token = base_url.rstrip('/'), token
        self.client = client or httpx.Client(timeout=10, follow_redirects=False, trust_env=False)

    def _post(self, path, payload, request_id):
        with self.client.stream('POST', self.base_url + path, json=payload,
                                headers={'Authorization': 'Bearer ' + self.token, 'Idempotency-Key': request_id},
                                timeout=10, follow_redirects=False) as response:
            response.raise_for_status()
            parts, size = [], 0
            for part in response.iter_bytes():
                size += len(part)
                if size > 10 * 1024 * 1024:
                    raise InputError('Connector response exceeds the size limit.')
                parts.append(part)
        return strict_json(b''.join(parts))

    def revoke(self, request):
        return self._post('/revocations', request, request['request_id'])

    def scan(self, source, request_id):
        return self._post('/scans', {'source': source, 'request_id': request_id}, request_id)


class FixtureConnector:
    """Simulates a connector against its own persistent fixture, never a host OS."""
    def __init__(self, state_path, initial_scan=None, *, clock=utcnow):
        self.path, self.clock = str(Path(state_path).resolve()), clock
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(self.path, timeout=10)) as conn, conn:
            conn.execute('CREATE TABLE IF NOT EXISTS state(id INTEGER PRIMARY KEY CHECK(id=1), payload TEXT NOT NULL)')
            conn.execute('CREATE TABLE IF NOT EXISTS receipts(id TEXT PRIMARY KEY, digest TEXT NOT NULL, payload TEXT NOT NULL)')
            if not conn.execute('SELECT 1 FROM state').fetchone():
                if initial_scan is None:
                    raise InputError('A new fixture connector requires an initial synthetic scan.')
                Scan.model_validate(initial_scan)
                conn.execute('INSERT INTO state VALUES(1,?)', (canonical(initial_scan),))

    def revoke(self, request):
        with closing(sqlite3.connect(self.path, timeout=10)) as conn, conn:
            conn.execute('BEGIN IMMEDIATE')
            prior = conn.execute('SELECT digest,payload FROM receipts WHERE id=?', (request['request_id'],)).fetchone()
            if prior:
                if prior[0] != digest(request):
                    raise InputError('The same request ID was reused with different content.')
                return json.loads(prior[1])
            state = json.loads(conn.execute('SELECT payload FROM state WHERE id=1').fetchone()[0])
            if request['source'] != state['source'] or request['mapping_version'] != state['mapping_version'] or request['entitlement'] not in state['scope_entitlements']:
                raise InputError('Approved target does not match the simulated source scope.')
            state['assignments'] = [a for a in state['assignments'] if not
                                    (a['identity'] == request['identity'] and a['entitlement'] == request['entitlement'])]
            conn.execute('UPDATE state SET payload=? WHERE id=1', (canonical(state),))
            response = {'request_id': request['request_id'], 'status': 'succeeded', 'message': 'Simulated removal accepted; a separate fixture scan is required.'}
            conn.execute('INSERT INTO receipts VALUES(?,?,?)', (request['request_id'], digest(request), canonical(response)))
            return response

    def scan(self, source, request_id):
        with closing(sqlite3.connect(self.path, timeout=10)) as conn, conn:
            state = json.loads(conn.execute('SELECT payload FROM state WHERE id=1').fetchone()[0])
        if state['source'] != source:
            raise InputError('Wrong simulated source requested.')
        state.update(scan_id='scan:' + str(uuid4()), scanned_at=timestamp(self.clock()), request_id=request_id)
        return state
