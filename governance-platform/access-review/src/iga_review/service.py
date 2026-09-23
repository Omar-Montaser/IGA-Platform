"""Review orchestration, authorization, durable approvals and verification."""
from dataclasses import asdict
from datetime import timedelta
import hashlib
import hmac
import json
from uuid import uuid4

from iga_hr import validate_documents
from .domain import CampaignInput, DecisionInput, EngineConfig, InputError, Scan, canonical, digest, instant, timestamp, utcnow
from .engine import ENGINE_VERSION, evaluate, evidence_warnings
from .explanations import RuleReviewer
from .store import Store

MIN_AI_CONFIDENCE = 0.7


class ServiceError(Exception):
    def __init__(self, status, code, message):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


class ReviewService:
    def __init__(self, db_path, users, *, fallback_reviewer_id=None, connectors=None,
                 explainer=None, config=EngineConfig(), clock=utcnow, demo=False,
                 allow_external_ai_data=False):
        self.store = Store(db_path)
        self.users = {u.id: u for u in users}
        if len(self.users) != len(users) or not users:
            raise ValueError('Unique configured users are required')
        if any(u.role not in ('admin', 'reviewer') or len(u.token_hash) != 64 for u in users):
            raise ValueError('Invalid principal configuration')
        if len({u.token_hash for u in users}) != len(users):
            raise ValueError('Credentials must uniquely identify a principal')
        hr_ids = [u.hr_identity_id for u in users if u.hr_identity_id is not None]
        if len(hr_ids) != len(set(hr_ids)):
            raise ValueError('HR principal mappings must be unique')
        if fallback_reviewer_id is not None and fallback_reviewer_id not in self.users:
            raise ValueError('Fallback reviewer is not configured')
        self.fallback = fallback_reviewer_id
        self.connectors = connectors or {}
        self.reviewer = explainer or RuleReviewer()
        self.explainer = self.reviewer
        self.config, self.clock, self.demo = config, clock, demo
        self.allow_external_ai_data = allow_external_ai_data

    def authenticate(self, token):
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        for user in self.users.values():
            if hmac.compare_digest(user.token_hash, token_hash):
                return user
        raise ServiceError(401, 'unauthenticated', 'A valid reviewer credential is required.')

    def _admin(self, actor):
        if actor.role != 'admin':
            raise ServiceError(403, 'forbidden', 'Administrator permission is required.')

    def _route(self, finding, bundle):
        person = bundle.identity_by_id(finding['identity_id'])
        if person and person.manager_id:
            manager = next((u for u in self.users.values() if u.hr_identity_id == person.manager_id), None)
            if manager:
                return manager.id, 'HR manager'
        return self.fallback, 'Configured fallback reviewer' if self.fallback else 'No configured reviewer; routing unresolved'

    def _visible(self, row, actor):
        return actor.role == 'admin' or row['reviewer_id'] == actor.id

    def _require_row(self, conn, finding_id, actor):
        row = conn.execute('SELECT * FROM findings WHERE id=?', (finding_id,)).fetchone()
        if row is None or not self._visible(row, actor):
            raise ServiceError(404, 'not_found', 'Review item was not found.')
        return row

    def _quality(self, campaign):
        inputs = CampaignInput.model_validate(json.loads(campaign['inputs_json']))
        bundle = validate_documents(inputs.identities, inputs.policies)
        warnings = evidence_warnings(bundle, inputs.scan, self.clock(), self.config)
        if campaign['superseded_by']:
            warnings.append('This campaign was superseded by a newer imported review for this source.')
        return warnings

    def _review_cases(self, cases):
        results = []
        for case in cases:
            try:
                assessment = self.reviewer.review(case)
            except Exception:
                assessment = RuleReviewer().review(case)
                assessment['fallback_reason'] = 'reviewer_failed'
            assessments = {row['item_key']: row for row in assessment['item_assessments']}
            reasons = set()
            if assessment['status'] != 'ready':
                reasons.add('ai_fallback')
            if assessment['confidence'] < MIN_AI_CONFIDENCE:
                reasons.add('low_ai_confidence')
            if assessment['missing_evidence']:
                reasons.add('missing_evidence')
            if assessment['open_questions']:
                reasons.add('open_questions')
            if case.get('evidence_gaps'):
                reasons.add('evidence_gaps')
            for item in case['items']:
                if item['privileged']:
                    reasons.add('privileged_access')
                proposed = assessments[item['key']]['action']
                for constraint in item['constraints']:
                    if constraint['effect'] == 'non_discretionary':
                        reasons.add('non_discretionary_constraint')
                        if proposed != constraint['required_action']:
                            reasons.add('ai_engine_disagreement')
            results.append(('case:' + str(uuid4()), case, assessment, sorted(reasons)))
        return results

    def _finding(self, row, actor, warnings):
        item = json.loads(row['payload_json'])
        self_review = bool(actor.hr_identity_id and actor.hr_identity_id == item['identity_id'])
        constraints = item.get('constraints', [])
        constraint_blockers = [c['text'] for c in constraints if c['effect'] == 'decision_blocked']
        can_decide = (not warnings and row['status'] == 'pending' and row['reviewer_id'] is not None
                      and not constraint_blockers and not self_review and self._visible(row, actor))
        actions = ['certify', 'revoke'] if item['kind'] == 'assignment' else ['acknowledge']
        required = {c['required_action'] for c in constraints if c['effect'] == 'non_discretionary'}
        if required:
            actions = [a for a in actions if {'certify': 'retain', 'revoke': 'remove', 'acknowledge': 'investigate'}[a] in required]
        item.update(id=row['id'], campaign_id=row['campaign_id'], status=row['status'], version=row['version'],
                    reviewer_id=row['reviewer_id'], routing_reason=row['routing_reason'],
                    explanation=json.loads(row['explanation_json']), can_decide=can_decide,
                    allowed_actions=actions if can_decide else [],
                    decision_blockers=list(dict.fromkeys(warnings + constraint_blockers)) + (['Self-review is not permitted.'] if self_review else []) +
                        (['Reviewer routing is unresolved.'] if row['reviewer_id'] is None else []))
        return item

    def create_campaign(self, payload, actor, *, raw_json=None):
        self._admin(actor)
        inputs = CampaignInput.model_validate(payload)
        bundle = validate_documents(inputs.identities, inputs.policies)
        # Enforce consent at ingestion, not merely CLI startup: a demo server
        # can receive arbitrary imports and service callers may bypass the CLI.
        if not bundle.synthetic and getattr(self.reviewer, 'provider', 'external') != 'rules' and not self.allow_external_ai_data:
            raise ServiceError(403, 'ai_data_consent_required',
                               'External AI review of non-synthetic data requires explicit data-owner approval.')
        result = evaluate(bundle, inputs.scan, inputs.correlations, now=self.clock(), config=self.config)
        content = inputs.model_dump()
        fingerprint = digest({'inputs': content, 'engine': ENGINE_VERSION, 'configuration': asdict(self.config)})
        now = timestamp(self.clock())
        campaign_id = 'review:' + str(uuid4())
        with self.store.read() as conn:
            duplicate = conn.execute('SELECT id FROM campaigns WHERE input_digest=?', (fingerprint,)).fetchone()
        if duplicate:
            return self.get_campaign(duplicate['id'], actor)
        # Provider calls happen outside the write transaction. Results are
        # validated/fallback-complete before any campaign state is committed.
        case_results = self._review_cases(result['cases'])
        with self.store.transaction() as conn:
            duplicate = conn.execute('SELECT id FROM campaigns WHERE input_digest=?', (fingerprint,)).fetchone()
            if duplicate:
                campaign_id = duplicate['id']
            else:
                known = conn.execute('SELECT digest FROM scans WHERE source=? AND scan_id=?', (inputs.scan.source, inputs.scan.scan_id)).fetchone()
                if known and known['digest'] != digest(inputs.scan.model_dump()):
                    raise ServiceError(409, 'scan_id_reused', 'A scan ID cannot identify different source evidence.')
                busy = conn.execute('SELECT 1 FROM requests r JOIN findings f ON f.id=r.finding_id JOIN campaigns c ON c.id=f.campaign_id WHERE c.source=? AND r.lease_until>? LIMIT 1', (inputs.scan.source, now)).fetchone()
                if busy:
                    raise ServiceError(409, 'source_busy', 'An approved operation is running for this source; retry import after it completes.')
                latest = conn.execute('SELECT inputs_json FROM campaigns WHERE source=? ORDER BY rowid DESC LIMIT 1', (inputs.scan.source,)).fetchone()
                if latest:
                    old = json.loads(latest['inputs_json'])
                    if instant(inputs.scan.scanned_at) < instant(old['scan']['scanned_at']) or instant(bundle.snapshot_at) < instant(old['identities']['snapshot_at']):
                        raise ServiceError(409, 'older_snapshot', 'An older scan or HR snapshot cannot replace the current source review.')
                conn.execute('INSERT OR IGNORE INTO scans VALUES(?,?,?)', (inputs.scan.source, inputs.scan.scan_id, digest(inputs.scan.model_dump())))
                metadata = {'warnings': result['warnings'], 'actionable': result['actionable'], 'engine_version': ENGINE_VERSION,
                             'engine_config': asdict(self.config), 'input_digests': {k: digest(content[k]) for k in ('identities', 'policies', 'scan', 'correlations')}}
                metadata['review'] = {'cases': len(case_results),
                                      'providers': sorted({assessment['provider'] for _, _, assessment, _ in case_results}),
                                      'fallback_cases': sum(assessment['status'] != 'ready' for _, _, assessment, _ in case_results),
                                      'low_confidence_threshold': MIN_AI_CONFIDENCE}
                conn.execute('INSERT INTO campaigns(id,name,source,created_at,inputs_json,raw_json,input_digest,metadata_json) VALUES(?,?,?,?,?,?,?,?)',
                             (campaign_id, inputs.name, inputs.scan.source, now, canonical(content), raw_json or canonical(content), fingerprint, canonical(metadata)))
                conn.execute('UPDATE campaigns SET superseded_by=? WHERE source=? AND id<>? AND superseded_by IS NULL', (campaign_id, inputs.scan.source, campaign_id))
                finding_count = 0
                for case_id, case, assessment, reasons in case_results:
                    conn.execute('INSERT INTO review_cases VALUES(?,?,?,?,?,?)',
                                 (case_id, campaign_id, canonical(case), canonical(assessment),
                                  bool(reasons), canonical(reasons)))
                    item_assessments = {row['item_key']: row for row in assessment['item_assessments']}
                    for finding in case['items']:
                        proposed = item_assessments[finding['key']]['action']
                        item_reasons = set(reasons)
                        finding = {**finding, 'case_id': case_id, 'case_assessment': assessment,
                                   'evidence_gaps': case.get('evidence_gaps', []),
                                   'review_evidence': {
                                       'assignments': [a for a in case['assignments'] if a['id'] in finding['assignment_ids']],
                                       'grant_paths': [p for p in case['grant_paths'] if p['id'] in finding['grant_path_ids']],
                                       'exceptions': [e for e in case['exceptions'] if e['account_id'] == finding['account_id'] and e['entitlement_id'] == finding['entitlement_id']],
                                       'history': [h for h in case['history'] if h['account_id'] == finding['account_id'] and h['entitlement_id'] in (None, finding['entitlement_id'])]},
                                   'item_assessment': item_assessments[finding['key']],
                                   'recommended_action': proposed,
                                   'recommendation': {'retain': 'certify', 'remove': 'revoke',
                                                      'investigate': 'review', 'escalate': 'review'}[proposed],
                                   'mandatory_human_review': bool(item_reasons),
                                   'human_review_reasons': sorted(item_reasons)}
                        finding_id = 'item:' + str(uuid4())
                        reviewer, routing = self._route(finding, bundle)
                        conn.execute('INSERT INTO findings(id,campaign_id,payload_json,reviewer_id,routing_reason,explanation_json) VALUES(?,?,?,?,?,?)',
                                     (finding_id, campaign_id, canonical(finding), reviewer, routing, canonical(assessment)))
                        finding_count += 1
                self.store.audit(conn, campaign_id, None, now, actor.id, 'campaign_imported',
                                 {'input_digest': fingerprint, 'source': inputs.scan.source,
                                  'cases': len(case_results), 'findings': finding_count,
                                  'warnings': result['warnings']})
        return self.get_campaign(campaign_id, actor)

    def get_campaign(self, campaign_id, actor):
        with self.store.read() as conn:
            row = conn.execute('SELECT * FROM campaigns WHERE id=?', (campaign_id,)).fetchone()
            if row is None:
                raise ServiceError(404, 'not_found', 'Campaign was not found.')
            rows = conn.execute('SELECT * FROM findings WHERE campaign_id=?', (campaign_id,)).fetchall()
            visible = [f for f in rows if self._visible(f, actor)]
            if actor.role != 'admin' and not visible:
                raise ServiceError(404, 'not_found', 'Campaign was not found.')
            warnings = self._quality(row)
            findings = sorted((self._finding(f, actor, warnings) for f in visible), key=lambda f: (-f['risk_score'], f['key']))
            return {'id': row['id'], 'name': row['name'], 'source': row['source'], 'created_at': row['created_at'],
                    'warnings': warnings, 'actionable': not warnings, 'superseded_by': row['superseded_by'],
                    'metadata': json.loads(row['metadata_json']), 'findings': findings,
                    'summary': {'total': len(findings), 'pending': sum(f['status'] == 'pending' for f in findings),
                                'critical': sum(f['risk_level'] == 'critical' for f in findings),
                                'high': sum(f['risk_level'] == 'high' for f in findings),
                                'verified': sum(f['status'] == 'revoked_verified' for f in findings)}}

    def list_campaigns(self, actor):
        with self.store.read() as conn:
            campaigns = conn.execute('SELECT * FROM campaigns ORDER BY rowid DESC').fetchall()
            result = []
            for row in campaigns:
                # For non-admin, check visibility: must have at least one visible finding
                if actor.role != 'admin':
                    visible = conn.execute('SELECT 1 FROM findings WHERE campaign_id=? AND reviewer_id=? LIMIT 1',
                                           (row['id'], actor.id)).fetchone()
                    if not visible:
                        continue

                # Compute summary counts without loading full finding payloads
                if actor.role == 'admin':
                    stats = conn.execute('''
                        SELECT status, payload_json FROM findings WHERE campaign_id=?
                    ''', (row['id'],)).fetchall()
                else:
                    stats = conn.execute('''
                        SELECT status, payload_json FROM findings WHERE campaign_id=? AND reviewer_id=?
                    ''', (row['id'], actor.id)).fetchall()

                # Extract risk_level and status from payload_json
                findings_data = [{'status': s['status'], **json.loads(s['payload_json'])} for s in stats]

                warnings = self._quality(row)
                result.append({
                    'id': row['id'], 'name': row['name'], 'source': row['source'],
                    'created_at': row['created_at'], 'warnings': warnings, 'actionable': not warnings,
                    'superseded_by': row['superseded_by'], 'metadata': json.loads(row['metadata_json']),
                    'summary': {
                        'total': len(findings_data),
                        'pending': sum(f['status'] == 'pending' for f in findings_data),
                        'critical': sum(f.get('risk_level') == 'critical' for f in findings_data),
                        'high': sum(f.get('risk_level') == 'high' for f in findings_data),
                        'verified': sum(f['status'] == 'revoked_verified' for f in findings_data)
                    }
                })
        return {'campaigns': result}

    def get_finding(self, finding_id, actor):
        with self.store.read() as conn:
            row = self._require_row(conn, finding_id, actor)
            campaign = conn.execute('SELECT * FROM campaigns WHERE id=?', (row['campaign_id'],)).fetchone()
            item = self._finding(row, actor, self._quality(campaign))
            request = conn.execute('SELECT id,state,last_error FROM requests WHERE finding_id=?', (finding_id,)).fetchone()
            item['remediation'] = dict(request) if request else None
            return item

    def decide(self, finding_id, actor, body, idempotency_key):
        decision = DecisionInput.model_validate(body)
        if not isinstance(idempotency_key, str) or not 8 <= len(idempotency_key) <= 128 or not all(c.isascii() and (c.isalnum() or c in '-_:.') for c in idempotency_key):
            raise ServiceError(400, 'idempotency_key', 'Supply an 8–128 character Idempotency-Key.')
        body_hash = digest({'finding_id': finding_id, **decision.model_dump()})
        now = timestamp(self.clock())
        with self.store.transaction() as conn:
            row = self._require_row(conn, finding_id, actor)
            prior = conn.execute('SELECT * FROM decisions WHERE actor_id=? AND idempotency_key=?', (actor.id, idempotency_key)).fetchone()
            if prior:
                if prior['body_digest'] != body_hash:
                    raise ServiceError(409, 'idempotency_conflict', 'This key already belongs to a different decision.')
                return json.loads(prior['payload_json'])
            campaign = conn.execute('SELECT * FROM campaigns WHERE id=?', (row['campaign_id'],)).fetchone()
            finding = self._finding(row, actor, self._quality(campaign))
            if row['version'] != decision.expected_version or row['status'] != 'pending':
                raise ServiceError(409, 'version_conflict', 'The item changed; refresh before deciding.')
            if not finding['can_decide']:
                raise ServiceError(403, 'decision_blocked', 'Evidence, reviewer routing, or self-review restrictions block this decision.')
            if decision.action not in finding['allowed_actions']:
                raise ServiceError(422, 'invalid_action', 'This action does not apply to this item.')
            required = {constraint['required_action'] for constraint in finding['constraints']
                        if constraint['effect'] == 'non_discretionary'}
            requested = {'certify': 'retain', 'revoke': 'remove', 'acknowledge': 'investigate'}[decision.action]
            if required and requested not in required:
                raise ServiceError(422, 'hard_constraint', 'The requested decision conflicts with a non-discretionary policy constraint.')
            if decision.action == 'certify' and (finding['recommendation'] != 'certify' or finding.get('mandatory_human_review')) and not decision.acknowledge_risk:
                raise ServiceError(422, 'risk_acknowledgement', 'Acknowledge the recorded risk before certifying this access.')
            decision_id = 'decision:' + str(uuid4())
            request_id = 'revoke:' + str(uuid4()) if decision.action == 'revoke' else None
            result = {'id': decision_id, 'finding_id': finding_id, 'actor_id': actor.id,
                      'action': decision.action, 'reason': decision.reason, 'acknowledge_risk': decision.acknowledge_risk,
                      'created_at': now, 'request_id': request_id}
            conn.execute('INSERT INTO decisions VALUES(?,?,?,?,?,?)', (decision_id, finding_id, actor.id, idempotency_key, body_hash, canonical(result)))
            new_status = {'certify': 'certified', 'acknowledge': 'acknowledged', 'revoke': 'revoke_queued'}[decision.action]
            conn.execute('UPDATE findings SET status=?,version=version+1 WHERE id=?', (new_status, finding_id))
            if request_id:
                request = {'request_id': request_id, 'source': finding['source'], 'identity': finding['account_id'],
                           'entitlement': finding['entitlement_id'], 'approved_by': actor.id, 'approved_at': now,
                           'reason': decision.reason, 'scan_id': finding['evidence']['scan_id'],
                           'mapping_version': finding['evidence']['mapping_version'],
                           'assignment_ids': finding['assignment_ids'], 'grant_path_ids': finding['grant_path_ids']}
                conn.execute('INSERT INTO requests(id,finding_id,state,payload_json) VALUES(?,?,?,?)', (request_id, finding_id, 'queued', canonical(request)))
            self.store.audit(conn, row['campaign_id'], finding_id, now, actor.id, 'decision_recorded', result)
        return result

    def explain(self, finding_id, actor):
        finding = self.get_finding(finding_id, actor)
        return finding['explanation']

    def process(self, campaign_id, actor):
        self._admin(actor)
        self.get_campaign(campaign_id, actor)
        with self.store.read() as conn:
            ids = [r[0] for r in conn.execute('SELECT r.id FROM requests r JOIN findings f ON f.id=r.finding_id WHERE f.campaign_id=? AND r.state IN (?,?,?)',
                                              (campaign_id, 'queued', 'dispatching', 'verification_pending'))]
        return {'processed': [self._work(request_id) for request_id in ids]}

    def retry(self, request_id, actor):
        self._admin(actor)
        with self.store.transaction() as conn:
            row = conn.execute('SELECT r.*,f.campaign_id FROM requests r JOIN findings f ON f.id=r.finding_id WHERE r.id=?', (request_id,)).fetchone()
            if not row:
                raise ServiceError(404, 'not_found', 'Remediation request was not found.')
            if row['state'] not in ('failed', 'verification_failed'):
                raise ServiceError(409, 'retry_blocked', 'Only failed work can be retried.')
            state = 'verification_pending' if row['state'] == 'verification_failed' else 'queued'
            conn.execute('UPDATE requests SET state=?,lease_until=NULL,last_error=NULL WHERE id=?', (state, request_id))
            self.store.audit(conn, row['campaign_id'], row['finding_id'], timestamp(self.clock()), actor.id, 'retry_requested', {'request_id': request_id, 'state': state})
        return self._work(request_id)

    def _work(self, request_id):
        now = self.clock()
        with self.store.transaction() as conn:
            row = conn.execute('SELECT r.*,f.campaign_id FROM requests r JOIN findings f ON f.id=r.finding_id WHERE r.id=?', (request_id,)).fetchone()
            if not row:
                raise ServiceError(404, 'not_found', 'Request was not found.')
            if row['state'] not in ('queued', 'dispatching', 'verification_pending'):
                return {'request_id': request_id, 'state': row['state']}
            if row['lease_until'] and instant(row['lease_until']) > now:
                return {'request_id': request_id, 'state': row['state'], 'busy': True}
            verifying = row['state'] == 'verification_pending'
            campaign = conn.execute('SELECT * FROM campaigns WHERE id=?', (row['campaign_id'],)).fetchone()
            approval = json.loads(row['payload_json'])
            approver = self.users.get(approval['approved_by'])
            finding_row = conn.execute('SELECT * FROM findings WHERE id=?', (row['finding_id'],)).fetchone()
            finding_payload = json.loads(finding_row['payload_json'])
            authorized = (approver is not None and self._visible(finding_row, approver)
                          and finding_row['reviewer_id'] is not None
                          and not (approver.hr_identity_id and approver.hr_identity_id == finding_payload['identity_id']))
            if not verifying and not authorized:
                self._finish(conn, row, 'failed', 'The approving principal is no longer authorized; create a fresh review.')
                return {'request_id': request_id, 'state': 'failed'}
            if not verifying and self._quality(campaign):
                self._finish(conn, row, 'failed', 'Evidence is stale, incomplete, or superseded; create a fresh review before dispatch.')
                return {'request_id': request_id, 'state': 'failed'}
            state = 'verification_pending' if verifying else 'dispatching'
            conn.execute('UPDATE requests SET state=?,lease_until=? WHERE id=?', (state, timestamp(now + timedelta(minutes=2)), request_id))
            self.store.audit(conn, row['campaign_id'], row['finding_id'], timestamp(now), 'system', 'verification_started' if verifying else 'dispatch_started', {'request_id': request_id})
            request = json.loads(row['payload_json'])
        connector = self.connectors.get(request['source'])
        try:
            if connector is None:
                raise InputError('No connector is configured for this source.')
            if not verifying:
                response = connector.revoke(request)
                if set(response) != {'request_id', 'status', 'message'} or response['request_id'] != request_id or response['status'] not in ('succeeded', 'failed') or not isinstance(response['message'], str):
                    raise InputError('Connector acknowledgement does not match the approved request.')
                if response['status'] == 'failed':
                    raise InputError('Connector reported that removal failed.')
                with self.store.transaction() as conn:
                    conn.execute('UPDATE requests SET state=? WHERE id=?', ('verification_pending', request_id))
                    conn.execute('UPDATE findings SET status=?,version=version+1 WHERE id=?', ('verification_pending', row['finding_id']))
                    self.store.audit(conn, row['campaign_id'], row['finding_id'], timestamp(self.clock()), 'system', 'connector_acknowledged', {'request_id': request_id})
            scan_request_id = 'rescan:' + str(uuid4())
            requested_at = self.clock()
            fresh_raw = connector.scan(request['source'], scan_request_id)
            fresh = Scan.model_validate(fresh_raw)
            problem = self._verification_problem(request, fresh, scan_request_id, requested_at)
            with self.store.transaction() as conn:
                known = conn.execute('SELECT digest FROM scans WHERE source=? AND scan_id=?', (fresh.source, fresh.scan_id)).fetchone()
                if known:
                    problem = problem or 'Verification scan ID was already used.'
                else:
                    conn.execute('INSERT INTO scans VALUES(?,?,?)', (fresh.source, fresh.scan_id, digest(fresh.model_dump())))
                evidence = {'scan': fresh.model_dump(), 'digest': digest(fresh.model_dump()), 'requested_at': timestamp(requested_at), 'request_id': scan_request_id}
                self._finish(conn, row, 'verification_failed' if problem else 'verified', problem, evidence)
            return {'request_id': request_id, 'state': 'verification_failed' if problem else 'verified', 'error': problem}
        except Exception as exc:
            # Do not leak credentials or remote response bodies into user-visible errors.
            message = str(exc) if isinstance(exc, InputError) else 'Connector interaction failed; retry the same approved request after checking the connector.'
            with self.store.transaction() as conn:
                current = conn.execute('SELECT state FROM requests WHERE id=?', (request_id,)).fetchone()['state']
                state = 'verification_failed' if current == 'verification_pending' else 'failed'
                self._finish(conn, row, state, message)
            return {'request_id': request_id, 'state': state, 'error': message}

    def _verification_problem(self, request, scan, request_id, requested_at):
        if scan.request_id != request_id or scan.source != request['source']:
            return 'Verification response has the wrong request or source.'
        if scan.scan_id == request['scan_id'] or scan.mapping_version != request['mapping_version']:
            return 'Verification needs a new scan with the same mapping version.'
        if instant(scan.scanned_at) < requested_at or instant(scan.scanned_at) <= instant(request['approved_at']):
            return 'Verification evidence predates this scan request or approval.'
        if (instant(scan.scanned_at) - self.clock()).total_seconds() > self.config.max_clock_skew_seconds:
            return 'Verification scan timestamp is too far in the future.'
        if not scan.complete or request['entitlement'] not in scan.scope_entitlements:
            return 'Verification scan does not completely cover the target capability.'
        if any(a.identity == request['identity'] and a.entitlement == request['entitlement'] for a in scan.assignments):
            return 'The capability still exists on the target account.'
        if any(p.account_id == request['identity'] and p.entitlement_id == request['entitlement'] for p in scan.grant_paths):
            return 'A grant path still carries the capability on the target account.'
        remaining_paths = {path.id for path in scan.grant_paths}
        if remaining_paths.intersection(request.get('grant_path_ids', ())):
            return 'An approved grant path still exists on the target account.'
        return None

    def _finish(self, conn, row, state, error=None, evidence=None):
        evidence_json = canonical(evidence) if evidence is not None else row['verification_json']
        conn.execute('UPDATE requests SET state=?,lease_until=NULL,last_error=?,verification_json=? WHERE id=?', (state, error, evidence_json, row['id']))
        item_state = {'verified': 'revoked_verified', 'verification_failed': 'verification_failed', 'failed': 'revoke_failed'}[state]
        conn.execute('UPDATE findings SET status=?,version=version+1 WHERE id=?', (item_state, row['finding_id']))
        self.store.audit(conn, row['campaign_id'], row['finding_id'], timestamp(self.clock()), 'system', state,
                         {'request_id': row['id'], 'error': error, 'verification': evidence})

    # ------------------------------------------------------------------
    # Live source view for the reviewer interface.
    #
    # Source independent by construction: everything below comes from the
    # normalized scan, so it reports accounts and generic entitlement IDs and
    # never a native group name. The core still contains no knowledge of what
    # kind of system is on the other end of the connector.
    # ------------------------------------------------------------------
    def environment(self, actor, *, max_age_seconds=5):
        """What the configured sources look like right now, plus recent
        connector activity. Admin only: it is a full read of every source."""
        self._admin(actor)
        now = self.clock()
        cached = getattr(self, '_environment_cache', None)
        if cached and (now - cached[0]).total_seconds() < max_age_seconds:
            payload = dict(cached[1], cached=True)
            payload['activity'] = self._connector_activity()
            return payload

        sources = []
        for source, connector in sorted(self.connectors.items()):
            try:
                # A request ID is required, not optional: HTTPConnector sends it
                # as the Idempotency-Key header, and None is not a legal header
                # value. Namespaced so it can never be mistaken for a
                # revocation request ID during verification.
                scan = Scan.model_validate(
                    connector.scan(source, 'env:' + str(uuid4())))
            except Exception as exc:
                # A source that cannot be read is reported as unavailable
                # rather than omitted; a blank panel would read as "no access
                # exists here", which is the opposite of the truth.
                sources.append({'source': source, 'status': 'unavailable',
                                'error': str(exc)[:300], 'counts': {}, 'accounts': []})
                continue
            held, direct, inherited = {}, {}, {}
            paths = {p.id: p for p in scan.grant_paths}
            for item in scan.assignments:
                held.setdefault(item.identity, []).append(item.entitlement)
                for path_id in item.grant_path_ids:
                    path = paths.get(path_id)
                    target = direct if path is not None and path.grant_type == 'direct' else inherited
                    target[item.identity] = target.get(item.identity, 0) + 1
            accounts = [{
                'id': a.id, 'username': a.username, 'enabled': a.enabled,
                'account_type': a.account_type,
                'entitlements': sorted(held.get(a.id, [])),
                'direct': direct.get(a.id, 0), 'inherited': inherited.get(a.id, 0),
            } for a in sorted(scan.identities, key=lambda a: a.username)]
            sources.append({
                'source': source, 'status': 'ok', 'error': None,
                'scan_id': scan.scan_id, 'scanned_at': scan.scanned_at,
                'complete': scan.complete, 'mapping_version': scan.mapping_version,
                'counts': {
                    'accounts': len(scan.identities),
                    'enabled': sum(1 for a in scan.identities if a.enabled),
                    'entitlements': len(scan.entitlements),
                    'assignments': len(scan.assignments),
                    'grant_paths': len(scan.grant_paths),
                    'direct': sum(1 for p in scan.grant_paths if p.grant_type == 'direct'),
                    'inherited': sum(1 for p in scan.grant_paths if p.grant_type == 'inherited'),
                    'unassigned_accounts': sum(1 for a in accounts if not a['entitlements']),
                },
                'accounts': accounts,
            })

        payload = {'generated_at': timestamp(now), 'cached': False, 'sources': sources}
        self._environment_cache = (now, payload)
        return dict(payload, activity=self._connector_activity())

    def _connector_activity(self, limit=30):
        """Recent remediation traffic between this core and the connectors."""
        rows = []
        with self.store.read() as conn:
            for row in conn.execute(
                    'SELECT r.id,r.state,r.last_error,r.payload_json,r.verification_json,'
                    'f.campaign_id FROM requests r JOIN findings f ON f.id=r.finding_id'):
                request = json.loads(row['payload_json'])
                verification = json.loads(row['verification_json']) if row['verification_json'] else None
                rows.append({
                    'request_id': row['id'], 'state': row['state'],
                    'campaign_id': row['campaign_id'], 'error': row['last_error'],
                    'source': request.get('source'), 'identity': request.get('identity'),
                    'entitlement': request.get('entitlement'),
                    'approved_at': request.get('approved_at'),
                    'verified_scan_id': (verification or {}).get('scan_id'),
                    'verified_at': (verification or {}).get('scanned_at'),
                })
        rows.sort(key=lambda r: r['verified_at'] or r['approved_at'] or '', reverse=True)
        return rows[:limit]

    def audit(self, campaign_id, actor):
        campaign = self.get_campaign(campaign_id, actor)
        visible = {f['id'] for f in campaign['findings']}
        events, previous, intact = [], '0' * 64, True
        with self.store.read() as conn:
            for row in conn.execute('SELECT * FROM audit ORDER BY seq'):
                payload = {'campaign_id': row['campaign_id'], 'finding_id': row['finding_id'], 'timestamp': row['timestamp'],
                           'actor_id': row['actor_id'], 'action': row['action'], 'data': json.loads(row['data_json']), 'previous_hash': row['previous_hash']}
                if row['previous_hash'] != previous or digest(payload) != row['event_hash']:
                    intact = False
                previous = row['event_hash']
                if row['campaign_id'] == campaign_id and (actor.role == 'admin' or row['finding_id'] in visible):
                    events.append({'seq': row['seq'], **payload, 'event_hash': row['event_hash']})
        return {'events': events, 'integrity': intact}

    def export(self, campaign_id, actor):
        self._admin(actor)
        campaign = self.get_campaign(campaign_id, actor)
        with self.store.read() as conn:
            row = conn.execute('SELECT inputs_json,raw_json,input_digest FROM campaigns WHERE id=?', (campaign_id,)).fetchone()
            decisions = [json.loads(r[0]) for r in conn.execute('SELECT d.payload_json FROM decisions d JOIN findings f ON f.id=d.finding_id WHERE f.campaign_id=?', (campaign_id,))]
            requests = []
            for r in conn.execute('SELECT r.* FROM requests r JOIN findings f ON f.id=r.finding_id WHERE f.campaign_id=?', (campaign_id,)):
                requests.append({'request': json.loads(r['payload_json']), 'state': r['state'], 'error': r['last_error'],
                                 'verification': json.loads(r['verification_json']) if r['verification_json'] else None})
            cases = [{'case': json.loads(r['payload_json']), 'assessment': json.loads(r['assessment_json']),
                      'mandatory_human_review': bool(r['mandatory_human_review']),
                      'human_review_reasons': json.loads(r['human_review_reasons_json'])}
                     for r in conn.execute('SELECT * FROM review_cases WHERE campaign_id=?', (campaign_id,))]
        return {'campaign': campaign, 'inputs': json.loads(row['inputs_json']), 'raw_import': row['raw_json'],
                'input_digest': row['input_digest'], 'cases': cases, 'decisions': decisions,
                'requests': requests, 'audit': self.audit(campaign_id, actor)}
