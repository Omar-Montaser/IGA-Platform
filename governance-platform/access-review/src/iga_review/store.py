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
            if version != 2:
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
