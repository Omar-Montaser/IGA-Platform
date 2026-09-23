"""SQLite transactions and an append-only audit chain for a single deployment."""
from contextlib import contextmanager, closing
from pathlib import Path
import sqlite3
from .domain import canonical, digest

SCHEMA = '''
CREATE TABLE IF NOT EXISTS meta(version INTEGER NOT NULL);
INSERT INTO meta SELECT 2 WHERE NOT EXISTS(SELECT 1 FROM meta);
CREATE TABLE IF NOT EXISTS campaigns(
 id TEXT PRIMARY KEY, name TEXT NOT NULL, source TEXT NOT NULL,
 created_at TEXT NOT NULL, inputs_json TEXT NOT NULL, raw_json TEXT NOT NULL,
 input_digest TEXT NOT NULL UNIQUE, metadata_json TEXT NOT NULL, superseded_by TEXT);
CREATE TABLE IF NOT EXISTS scans(source TEXT NOT NULL, scan_id TEXT NOT NULL,
 digest TEXT NOT NULL, PRIMARY KEY(source,scan_id));
CREATE TABLE IF NOT EXISTS review_cases(
 id TEXT PRIMARY KEY, campaign_id TEXT NOT NULL REFERENCES campaigns(id),
 payload_json TEXT NOT NULL, assessment_json TEXT NOT NULL,
 mandatory_human_review INTEGER NOT NULL, human_review_reasons_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS findings(
 id TEXT PRIMARY KEY, campaign_id TEXT NOT NULL REFERENCES campaigns(id),
 payload_json TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
 version INTEGER NOT NULL DEFAULT 1, reviewer_id TEXT, routing_reason TEXT NOT NULL,
 explanation_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS decisions(
 id TEXT PRIMARY KEY, finding_id TEXT NOT NULL REFERENCES findings(id),
 actor_id TEXT NOT NULL, idempotency_key TEXT NOT NULL, body_digest TEXT NOT NULL,
 payload_json TEXT NOT NULL, UNIQUE(actor_id,idempotency_key));
CREATE TABLE IF NOT EXISTS requests(
 id TEXT PRIMARY KEY, finding_id TEXT NOT NULL UNIQUE REFERENCES findings(id),
 state TEXT NOT NULL, payload_json TEXT NOT NULL, lease_until TEXT,
 last_error TEXT, verification_json TEXT);
CREATE TABLE IF NOT EXISTS audit(
 seq INTEGER PRIMARY KEY AUTOINCREMENT, campaign_id TEXT NOT NULL,
 finding_id TEXT, timestamp TEXT NOT NULL, actor_id TEXT NOT NULL,
 action TEXT NOT NULL, data_json TEXT NOT NULL, previous_hash TEXT NOT NULL,
 event_hash TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit
 BEGIN SELECT RAISE(ABORT,'audit is append only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit
 BEGIN SELECT RAISE(ABORT,'audit is append only'); END;
CREATE TRIGGER IF NOT EXISTS inputs_immutable BEFORE UPDATE OF inputs_json,raw_json,input_digest ON campaigns
 BEGIN SELECT RAISE(ABORT,'inputs are immutable'); END;
CREATE TRIGGER IF NOT EXISTS decision_no_update BEFORE UPDATE ON decisions
 BEGIN SELECT RAISE(ABORT,'decisions are immutable'); END;
CREATE TRIGGER IF NOT EXISTS decision_no_delete BEFORE DELETE ON decisions
 BEGIN SELECT RAISE(ABORT,'decisions are immutable'); END;
CREATE INDEX IF NOT EXISTS findings_campaign ON findings(campaign_id);
CREATE INDEX IF NOT EXISTS cases_campaign ON review_cases(campaign_id);
CREATE INDEX IF NOT EXISTS audit_campaign ON audit(campaign_id,seq);
CREATE TABLE IF NOT EXISTS campaign_runs(
 id TEXT PRIMARY KEY, source TEXT NOT NULL, name TEXT NOT NULL, actor_id TEXT NOT NULL,
 idempotency_key TEXT NOT NULL, body_digest TEXT NOT NULL,
 state TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 inputs_json TEXT NOT NULL, scan_json TEXT, scan_digest TEXT,
 campaign_id TEXT REFERENCES campaigns(id), attempts INTEGER NOT NULL DEFAULT 0,
 lease_token TEXT, lease_until TEXT, deadline TEXT, error TEXT, retryable INTEGER NOT NULL DEFAULT 0,
 UNIQUE(actor_id,idempotency_key));
CREATE UNIQUE INDEX IF NOT EXISTS runs_active_source ON campaign_runs(source)
 WHERE state IN ('queued','scanning','validating','reviewing');
CREATE TABLE IF NOT EXISTS inventory_snapshots(
 source TEXT NOT NULL, scan_id TEXT NOT NULL, observed_at TEXT NOT NULL,
 scan_json TEXT NOT NULL, digest TEXT NOT NULL, run_id TEXT NOT NULL REFERENCES campaign_runs(id),
 PRIMARY KEY(source,scan_id));
CREATE TABLE IF NOT EXISTS run_events(
 seq INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL REFERENCES campaign_runs(id),
 timestamp TEXT NOT NULL, state TEXT NOT NULL, message TEXT);
CREATE TRIGGER IF NOT EXISTS run_events_no_update BEFORE UPDATE ON run_events
 BEGIN SELECT RAISE(ABORT,'run events are append only'); END;
CREATE TRIGGER IF NOT EXISTS run_events_no_delete BEFORE DELETE ON run_events
 BEGIN SELECT RAISE(ABORT,'run events are append only'); END;
CREATE TRIGGER IF NOT EXISTS snapshot_no_update BEFORE UPDATE ON inventory_snapshots
 BEGIN SELECT RAISE(ABORT,'inventory snapshots are immutable'); END;
CREATE TRIGGER IF NOT EXISTS snapshot_no_delete BEFORE DELETE ON inventory_snapshots
 BEGIN SELECT RAISE(ABORT,'inventory snapshots are immutable'); END;
CREATE TRIGGER IF NOT EXISTS run_inputs_immutable BEFORE UPDATE OF inputs_json ON campaign_runs
 BEGIN SELECT RAISE(ABORT,'run inputs are immutable'); END;
CREATE TRIGGER IF NOT EXISTS run_scan_immutable BEFORE UPDATE OF scan_json,scan_digest ON campaign_runs
 WHEN OLD.scan_json IS NOT NULL
 BEGIN SELECT RAISE(ABORT,'accepted run scans are immutable'); END;
'''


class Store:
    def __init__(self, path):
        self.path = str(Path(path).resolve())
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with closing(self.connect()) as conn:
            conn.execute('PRAGMA journal_mode=WAL')
            conn.executescript(SCHEMA)
            version = conn.execute('SELECT version FROM meta').fetchone()[0]
            if version == 1:
                conn.execute('UPDATE meta SET version=2')
                version = 2
            if version == 2:
                conn.execute('UPDATE meta SET version=3')
                version = 3
            if version != 3:
                raise ValueError('Unsupported database schema version')

    def connect(self):
        conn = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA foreign_keys=ON')
        return conn

    @contextmanager
    def transaction(self):
        conn = self.connect()
        try:
            conn.execute('BEGIN IMMEDIATE')
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    @contextmanager
    def read(self):
        conn = self.connect()
        try:
            yield conn
        finally:
            conn.close()

    @staticmethod
    def audit(conn, campaign_id, finding_id, at, actor, action, data):
        prior = conn.execute('SELECT event_hash FROM audit ORDER BY seq DESC LIMIT 1').fetchone()
        previous = prior[0] if prior else '0' * 64
        payload = {'campaign_id': campaign_id, 'finding_id': finding_id, 'timestamp': at,
                   'actor_id': actor, 'action': action, 'data': data, 'previous_hash': previous}
        conn.execute('INSERT INTO audit(campaign_id,finding_id,timestamp,actor_id,action,data_json,previous_hash,event_hash) VALUES(?,?,?,?,?,?,?,?)',
                     (campaign_id, finding_id, at, actor, action, canonical(data), previous, digest(payload)))
