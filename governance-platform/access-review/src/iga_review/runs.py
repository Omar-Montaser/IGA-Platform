"""Durable environment-to-campaign jobs, with fenced leases and pinned evidence."""
from datetime import timedelta
import json
import logging
import sqlite3
import threading
from uuid import uuid4

from iga_hr import validate_documents, BundleValidationError
from pydantic import ValidationError
from .domain import Record, Scan, CampaignInput, InputError, canonical, digest, instant, timestamp
from .engine import evidence_warnings, evaluate
from .source_inputs import validate_binding_evidence
from .service import ServiceError

ACTIVE = ('queued', 'scanning', 'validating', 'reviewing')
MAX_ATTEMPTS = 3
LEASE_SECONDS = 30
ATTEMPT_SECONDS = 1800


class StartInput(Record):
    name: str


class LeaseLost(Exception):
    pass


class CampaignRuns:
    def __init__(self, service, environments=None):
        self.service, self.store = service, service.store
        self.environments = environments or {}

    def now(self):
        return timestamp(self.service.clock())

    def event(self, conn, run_id, state, message=None):
        conn.execute('INSERT INTO run_events(run_id,timestamp,state,message) VALUES(?,?,?,?)',
                     (run_id, self.now(), state, message))

    def public(self, row):
        return {key: row[key] for key in ('id', 'source', 'name', 'state', 'created_at', 'updated_at',
                                         'campaign_id', 'attempts', 'error')} | {
            'can_retry': bool(row['retryable'] and row['attempts'] < MAX_ATTEMPTS),
            'scan_id': json.loads(row['scan_json'])['scan_id'] if row['scan_json'] else None,
            'retry_guidance': ('Retry uses the accepted snapshot, if still fresh.' if row['scan_json']
                               else 'Retry requests a new observation.') if row['retryable'] else
                              ('Correct the setup or evidence and start a new review.' if row['state'] == 'blocked' else None)}

    def get(self, run_id, actor):
        self.service._admin(actor)
        with self.store.read() as conn:
            row = conn.execute('SELECT * FROM campaign_runs WHERE id=?', (run_id,)).fetchone()
            if not row:
                raise ServiceError(404, 'not_found', 'Review run was not found.')
            result = self.public(row)
            result['events'] = [dict(r) for r in conn.execute(
                'SELECT timestamp,state,message FROM run_events WHERE run_id=? ORDER BY seq', (run_id,))]
            if row['campaign_id']:
                campaign = conn.execute('SELECT metadata_json FROM campaigns WHERE id=?', (row['campaign_id'],)).fetchone()
                result['review'] = json.loads(campaign[0]).get('review')
            return result

    def configured_inputs(self, source):
        settings = self.environments.get(source, {})
        loader = settings.get('load_inputs')
        if not loader:
            raise ServiceError(409, 'setup_required', 'Configure HR identities, policies, and correlations for this environment.')
        try:
            docs = loader(self.service.clock())
            validate_documents(docs['identities'], docs['policies'])
            # Validate size/serialization now, before persisting any job.
            from .domain import strict_json
            strict_json(canonical(docs))
            return docs
        except (OSError, KeyError, TypeError, ValueError, BundleValidationError) as exc:
            raise ServiceError(409, 'setup_required', 'The configured HR/policy/correlation inputs are missing or invalid. Check the server input files.') from exc

    def check_source_free(self, conn, source, run_id=None):
        active = conn.execute("SELECT id FROM campaign_runs WHERE source=? AND state IN ('queued','scanning','validating','reviewing')",
                              (source,)).fetchone()
        if active and active['id'] != run_id:
            raise ServiceError(409, 'source_busy', 'A review is already running for this environment. Open its progress instead.')
        busy = conn.execute('SELECT 1 FROM requests r JOIN findings f ON f.id=r.finding_id JOIN campaigns c ON c.id=f.campaign_id '
                            "WHERE c.source=? AND (r.lease_until>? OR r.state IN ('dispatching','verification_pending')) LIMIT 1", (source, self.now())).fetchone()
        if busy:
            raise ServiceError(409, 'source_busy', 'An approved source operation is running. Retry after verification completes.')

    def start(self, source, payload, actor, key):
        self.service._admin(actor)
        request = StartInput.model_validate(payload)
        if not isinstance(key, str) or not 1 <= len(key) <= 200 or any(ord(c) < 33 or ord(c) > 126 for c in key):
            raise ServiceError(422, 'idempotency_key', 'A bounded printable Idempotency-Key is required.')
        fingerprint = digest({'source': source, 'name': request.name})
        with self.store.read() as conn:
            prior = conn.execute('SELECT * FROM campaign_runs WHERE actor_id=? AND idempotency_key=?', (actor.id, key)).fetchone()
        if prior:
            if prior['body_digest'] != fingerprint:
                raise ServiceError(409, 'idempotency_conflict', 'This request key was already used for different content.')
            return self.get(prior['id'], actor)
        if source not in self.service.connectors:
            raise ServiceError(404, 'not_found', 'Configured environment was not found.')
        docs = self.configured_inputs(source)
        # Pin adapter metadata with the input documents, too.
        settings = self.environments.get(source, {})
        pinned = {'documents': docs, 'mapping_version': settings.get('mapping_version'),
                  'correlation_mode': settings.get('correlation_mode'),
                  'input_digests': {k: digest(v) for k, v in docs.items()}}
        run_id, now = 'run:' + str(uuid4()), self.now()
        with self.store.transaction() as conn:
            prior = conn.execute('SELECT * FROM campaign_runs WHERE actor_id=? AND idempotency_key=?', (actor.id, key)).fetchone()
            if prior:
                if prior['body_digest'] != fingerprint:
                    raise ServiceError(409, 'idempotency_conflict', 'This request key was already used for different content.')
                run_id = prior['id']
            else:
                self.check_source_free(conn, source)
                conn.execute('INSERT INTO campaign_runs(id,source,name,actor_id,idempotency_key,body_digest,state,created_at,updated_at,inputs_json) '
                             'VALUES(?,?,?,?,?,?,?,?,?,?)', (run_id, source, request.name, actor.id, key, fingerprint, 'queued', now, now, canonical(pinned)))
                self.event(conn, run_id, 'queued')
        return self.get(run_id, actor)

    def retry(self, run_id, actor):
        self.service._admin(actor)
        with self.store.transaction() as conn:
            row = conn.execute('SELECT * FROM campaign_runs WHERE id=?', (run_id,)).fetchone()
            if not row:
                raise ServiceError(404, 'not_found', 'Review run was not found.')
            if row['state'] in ACTIVE or row['state'] == 'completed':
                return self.public(row)
            if not row['retryable'] or row['attempts'] >= MAX_ATTEMPTS:
                raise ServiceError(409, 'not_retryable', 'Correct the problem and start a new review.')
            self.check_source_free(conn, row['source'])
            conn.execute("UPDATE campaign_runs SET state='queued',error=NULL,retryable=0,lease_token=NULL,lease_until=NULL,updated_at=? WHERE id=?", (self.now(), run_id))
            self.event(conn, run_id, 'queued', 'Retry requested by ' + actor.id)
        return self.get(run_id, actor)

    def guard(self, conn, run_id, token):
        row = conn.execute('SELECT * FROM campaign_runs WHERE id=?', (run_id,)).fetchone()
        now = self.service.clock()
        if not row or row['state'] not in ACTIVE or row['lease_token'] != token or not row['lease_until'] or instant(row['lease_until']) <= now or instant(row['deadline']) <= now:
            raise LeaseLost()
        return row

    def stage(self, run_id, token, state):
        with self.store.transaction() as conn:
            self.guard(conn, run_id, token)
            conn.execute('UPDATE campaign_runs SET state=?,updated_at=? WHERE id=?', (state, self.now(), run_id))
            self.event(conn, run_id, state)

    def finish(self, conn, run_id, token, campaign_id):
        self.guard(conn, run_id, token)
        conn.execute("UPDATE campaign_runs SET state='completed',campaign_id=?,updated_at=?,lease_token=NULL,lease_until=NULL,error=NULL,retryable=0 WHERE id=?",
                     (campaign_id, self.now(), run_id))
        self.event(conn, run_id, 'completed')

    def claim(self):
        now = self.service.clock()
        with self.store.transaction() as conn:
            rows = conn.execute("SELECT * FROM campaign_runs WHERE state IN ('queued','scanning','validating','reviewing') ORDER BY rowid").fetchall()
            for row in rows:
                if row['lease_until'] and instant(row['lease_until']) > now and instant(row['deadline']) > now:
                    continue
                if row['attempts'] >= MAX_ATTEMPTS:
                    conn.execute("UPDATE campaign_runs SET state='failed',error=?,retryable=0,updated_at=?,lease_token=NULL,lease_until=NULL WHERE id=?",
                                 ('Worker recovery limit reached. Start a new review.', self.now(), row['id']))
                    self.event(conn, row['id'], 'failed', 'Recovery limit reached.')
                    continue
                token = str(uuid4())
                conn.execute('UPDATE campaign_runs SET lease_token=?,lease_until=?,deadline=?,attempts=attempts+1,updated_at=? WHERE id=?',
                             (token, timestamp(now + timedelta(seconds=LEASE_SECONDS)), timestamp(now + timedelta(seconds=ATTEMPT_SECONDS)), self.now(), row['id']))
                self.event(conn, row['id'], row['state'], 'Worker claimed attempt ' + str(row['attempts'] + 1))
                return row['id'], token
        return None

    def heartbeat(self, run_id, token, stopped, shutdown=None):
        while not stopped.wait(1):
            try:
                with self.store.transaction() as conn:
                    self.guard(conn, run_id, token)
                    if shutdown is not None and shutdown.is_set():
                        # Leave durable work recoverable, but fence this process.
                        conn.execute('UPDATE campaign_runs SET lease_until=?,deadline=? WHERE id=?',
                                     (self.now(), self.now(), run_id))
                        return
                    conn.execute('UPDATE campaign_runs SET lease_until=? WHERE id=?',
                                 (timestamp(self.service.clock() + timedelta(seconds=LEASE_SECONDS)), run_id))
            except (LeaseLost, sqlite3.Error):
                return

    def execute(self, run_id, token):
        with self.store.read() as conn:
            row = self.guard(conn, run_id, token)
        actor = self.service.users.get(row['actor_id'])
        if actor is None or actor.role != 'admin':
            raise ServiceError(403, 'forbidden', 'The initiating administrator is no longer authorized.')
        pinned = json.loads(row['inputs_json'])
        docs = pinned['documents']
        bundle = validate_documents(docs['identities'], docs['policies'])
        if not bundle.synthetic and self.service.reviewer.provider != 'rules' and not self.service.allow_external_ai_data:
            raise ServiceError(403, 'ai_data_consent_required', 'External AI review requires data-owner approval; configure consent or rules mode.')
        connector = self.service.connectors.get(row['source'])
        if connector is None:
            raise ServiceError(409, 'setup_required', 'This environment no longer has a configured connector.')
        if row['scan_json']:
            scan = Scan.model_validate(json.loads(row['scan_json']))
        else:
            self.stage(run_id, token, 'scanning')
            request_id = 'campaign-scan:' + str(uuid4())
            requested_at = self.service.clock()
            scan = Scan.model_validate(connector.scan(row['source'], request_id))
            self.stage(run_id, token, 'validating')
            if scan.source != row['source'] or scan.request_id != request_id:
                raise InputError('Connector response source or request ID does not match this run.')
            if instant(scan.scanned_at) < requested_at:
                raise InputError('Connector returned evidence older than this scan request.')
            if (instant(scan.scanned_at) - self.service.clock()).total_seconds() > self.service.config.max_clock_skew_seconds:
                raise InputError('Connector observation time is too far in the future.')
            if pinned['mapping_version'] and scan.mapping_version != pinned['mapping_version']:
                raise InputError('Connector mapping version differs from the configured version.')
            raw, fingerprint = canonical(scan.model_dump()), digest(scan.model_dump())
            with self.store.transaction() as conn:
                self.guard(conn, run_id, token)
                known = conn.execute('SELECT digest FROM scans WHERE source=? AND scan_id=?', (scan.source, scan.scan_id)).fetchone()
                if known:
                    raise InputError('A fresh campaign scan must use a new scan ID.')
                conn.execute('INSERT INTO scans VALUES(?,?,?)', (scan.source, scan.scan_id, fingerprint))
                conn.execute('INSERT INTO inventory_snapshots VALUES(?,?,?,?,?,?)', (scan.source, scan.scan_id, scan.scanned_at, raw, fingerprint, run_id))
                conn.execute('UPDATE campaign_runs SET scan_json=?,scan_digest=? WHERE id=?', (raw, fingerprint, run_id))
                self.event(conn, run_id, 'validating', 'Accepted scan ' + scan.scan_id)
        self.stage(run_id, token, 'validating')
        warnings = evidence_warnings(bundle, scan, self.service.clock(), self.service.config)
        if warnings:
            raise InputError(' '.join(warnings))
        payload = {'name': row['name'], **docs, 'scan': scan.model_dump()}
        inputs = CampaignInput.model_validate(payload)
        validate_binding_evidence(scan, docs['correlations'], pinned['correlation_mode'])
        # This catches invalid correlation references before external inference.
        evaluate(bundle, scan, inputs.correlations, now=self.service.clock(), config=self.service.config)
        self.stage(run_id, token, 'reviewing')
        self.service.create_campaign(payload, actor, run_context=(run_id, token))

    def tick(self, stop=None):
        if stop is not None and stop.is_set():
            return False
        claimed = self.claim()
        if not claimed:
            return False
        run_id, token = claimed
        heartbeat_stop = threading.Event()
        heartbeat = threading.Thread(target=self.heartbeat, args=(run_id, token, heartbeat_stop, stop), daemon=True)
        heartbeat.start()
        # Supervise blocking connector/provider calls independently. A timed-out
        # call cannot be killed safely in Python, but it must not hold this
        # worker forever or commit after shutdown/recovery.
        done, errors = threading.Event(), []
        def execute():
            try:
                self.execute(run_id, token)
            except BaseException as exc:
                errors.append(exc)
            finally:
                done.set()
        execution = threading.Thread(target=execute, name='campaign-attempt', daemon=True)
        execution.start()
        try:
            while not done.wait(.25):
                with self.store.read() as conn:
                    row = conn.execute('SELECT * FROM campaign_runs WHERE id=?', (run_id,)).fetchone()
                if row['state'] not in ACTIVE or row['lease_token'] != token:
                    raise LeaseLost()
                shutting_down = stop is not None and stop.is_set()
                if shutting_down or instant(row['deadline']) <= self.service.clock():
                    with self.store.transaction() as conn:
                        current = conn.execute('SELECT lease_token FROM campaign_runs WHERE id=?', (run_id,)).fetchone()
                        if current['lease_token'] != token:
                            raise LeaseLost()
                        conn.execute('UPDATE campaign_runs SET lease_until=?,deadline=? WHERE id=?',
                                     (self.now(), self.now(), run_id))
                        self.event(conn, run_id, row['state'],
                                   'Worker stopped; recovery pending.' if shutting_down else 'Attempt timed out; recovery pending.')
                        # Raise outside the transaction so fencing commits.
                    break
                with self.store.read() as conn:
                    self.guard(conn, run_id, token)
            else:
                if errors:
                    raise errors[0]
                return True
            raise LeaseLost()
        except LeaseLost:
            pass  # Fencing prevents an expired worker from committing anything.
        except Exception as exc:
            blocked = isinstance(exc, (InputError, ValidationError, BundleValidationError)) or (
                isinstance(exc, ServiceError) and exc.code != 'source_busy')
            message = (str(exc) if type(exc) is InputError else exc.message if isinstance(exc, ServiceError) else
                       'Input evidence is invalid. Check the configured documents and connector mapping.') if blocked else (
                       'Scan or review processing failed. Check the connector and server, then retry.')
            try:
                with self.store.transaction() as conn:
                    row = self.guard(conn, run_id, token)
                    state = 'blocked' if blocked else 'failed'
                    conn.execute('UPDATE campaign_runs SET state=?,error=?,retryable=?,updated_at=?,lease_token=NULL,lease_until=NULL WHERE id=?',
                                 (state, message[:600], not blocked and row['attempts'] < MAX_ATTEMPTS, self.now(), run_id))
                    self.event(conn, run_id, state, message[:600])
            except LeaseLost:
                pass
        finally:
            heartbeat_stop.set()
            heartbeat.join(timeout=1)
            execution.join(timeout=1)
        return True

    def environments_view(self, actor):
        self.service._admin(actor)
        sources = []
        with self.store.read() as conn:
            for source in sorted(self.service.connectors):
                settings = self.environments.get(source, {})
                row = conn.execute("SELECT * FROM campaign_runs WHERE source=? ORDER BY state IN ('queued','scanning','validating','reviewing') DESC,rowid DESC LIMIT 1", (source,)).fetchone()
                snapshot = conn.execute('SELECT scan_json FROM inventory_snapshots WHERE source=? ORDER BY observed_at DESC,rowid DESC LIMIT 1', (source,)).fetchone()
                latest = conn.execute('SELECT id,name,inputs_json,metadata_json FROM campaigns WHERE source=? ORDER BY rowid DESC LIMIT 1', (source,)).fetchone()
                # Existing deployments can show their immutable imported snapshot.
                scan_data = json.loads(snapshot[0]) if snapshot else json.loads(latest['inputs_json'])['scan'] if latest else None
                if latest:
                    imported = json.loads(latest['inputs_json'])['scan']
                    if scan_data is None or instant(imported['scanned_at']) > instant(scan_data['scanned_at']):
                        scan_data = imported
                error = None
                try:
                    self.configured_inputs(source)
                except ServiceError as exc:
                    error = exc.message
                item = {'source': source, 'name': settings.get('name', source), 'mode': settings.get('mode', 'unknown'),
                        'status': row['state'] if row and row['state'] in ACTIVE + ('failed', 'blocked') else 'last_known' if scan_data else 'never_scanned',
                        'setup_error': error, 'can_start': error is None and not (row and row['state'] in ACTIVE),
                        'run': self.public(row) | {'events': [dict(event) for event in conn.execute(
                            'SELECT timestamp,state,message FROM run_events WHERE run_id=? ORDER BY seq', (row['id'],))]} if row else None,
                        'latest_campaign': {'id': latest['id'], 'name': latest['name'], 'review': json.loads(latest['metadata_json']).get('review')} if latest else None,
                        'inventory': inventory(scan_data) if scan_data else None}
                sources.append(item)
        return {'generated_at': self.now(), 'sources': sources}


def inventory(scan):
    paths = {p['id']: p for p in scan['grant_paths']}
    held = {}
    for assignment in scan['assignments']:
        held.setdefault(assignment['identity'], []).append(assignment)
    accounts = []
    for account in scan['identities']:
        assignments = held.get(account['id'], [])
        grant_paths = [paths[p] for a in assignments for p in a['grant_path_ids']]
        accounts.append({**account, 'entitlements': sorted({a['entitlement'] for a in assignments}),
                         'direct': sum(p['grant_type'] == 'direct' for p in grant_paths),
                         'inherited': sum(p['grant_type'] == 'inherited' for p in grant_paths)})
    return {'scan_id': scan['scan_id'], 'scanned_at': scan['scanned_at'], 'complete': scan['complete'],
            'mapping_version': scan['mapping_version'], 'accounts': sorted(accounts, key=lambda a: a['username']),
            'counts': {'accounts': len(accounts), 'assignments': len(scan['assignments']),
                       'entitlements': len(scan['entitlements']), 'unassigned_accounts': sum(not a['entitlements'] for a in accounts)}}


class CampaignRunWorker:
    """ASGI lifespan owns the runner; SQLite owns its durable work and leases."""
    def __init__(self, runs):
        self.runs, self.stop = runs, threading.Event()
        self.thread = threading.Thread(target=self.loop, name='campaign-runs', daemon=True)

    def loop(self):
        while not self.stop.is_set():
            try:
                self.runs.tick(self.stop)
            except Exception:
                logging.getLogger(__name__).error('Campaign worker could not claim work; will retry.')
            self.stop.wait(1)

    def start(self):
        self.thread.start()

    def close(self):
        self.stop.set()
        self.thread.join(timeout=5)
