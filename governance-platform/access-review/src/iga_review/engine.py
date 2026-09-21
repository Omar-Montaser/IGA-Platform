"""Deterministic policy, peer and heuristic risk evaluation; no side effects."""
from collections import defaultdict
from datetime import datetime, timezone
from .domain import EngineConfig, InputError, digest, instant

ENGINE_VERSION = '1.0.0'
SENSITIVITY = {'unknown': 20, 'low': 0, 'medium': 5, 'high': 10, 'critical': 20}
POINTS = {'expected': 0, 'permitted_privileged': 10, 'restricted': 65,
          'lifecycle_restricted': 75, 'unauthorized_privilege': 65, 'unlisted': 30,
          'unknown_entitlement': 45, 'unmatched': 55, 'ambiguous': 60,
          'missing_expected': 20, 'coverage_gap': 20}
MESSAGES = {
    'expected': 'Access matches the role baseline.',
    'permitted_privileged': 'Elevated access is permitted for this role but is optional.',
    'restricted': 'The role policy explicitly forbids this access.',
    'lifecycle_restricted': 'The HR lifecycle policy permits no access in this employment status.',
    'unauthorized_privilege': 'Elevated access is outside the role’s permitted access lists.',
    'unlisted': 'This capability is not covered by the role’s allowed or restricted lists.',
    'unknown_entitlement': 'This discovered capability is absent from the authoritative policy catalog.',
    'unmatched': 'No explicit HR binding establishes ownership of this source account.',
    'ambiguous': 'Multiple HR bindings claim this source account; ownership needs resolution.',
    'missing_expected': 'Complete in-scope evidence contains no grant of this expected capability across the person’s linked accounts.',
    'coverage_gap': 'Evidence is incomplete or outside freshness limits; decisions are blocked.',
}


def evidence_warnings(bundle, scan, now, config):
    if now.tzinfo is None:
        raise InputError('Evaluation time must have a timezone')
    hr_time, scan_time = instant(bundle.snapshot_at), instant(scan.scanned_at)
    warnings = []
    if (now - hr_time).total_seconds() > config.max_hr_age_days * 86400:
        warnings.append('HR snapshot exceeds the configured freshness limit.')
    if (now - scan_time).total_seconds() > config.max_scan_age_hours * 3600:
        warnings.append('Scan exceeds the configured freshness limit.')
    if any((x - now).total_seconds() > config.max_clock_skew_seconds for x in (hr_time, scan_time)):
        warnings.append('Evidence timestamp is too far in the future.')
    if scan_time < hr_time or scan_time.date() < datetime.fromisoformat(bundle.effective_from).date():
        warnings.append('Scan predates the HR snapshot or policy effective date.')
    if any((p.status in ('active', 'on_leave') and p.end_date is not None and datetime.fromisoformat(p.end_date).date() <= now.date()) or (p.status == 'pre_hire' and datetime.fromisoformat(p.start_date).date() <= now.date()) for p in bundle.identities):
        warnings.append('Known employment lifecycle boundaries have passed; refresh the HR snapshot before deciding.')
    if not scan.complete:
        warnings.append('Source scan is partial; absence and peer inferences are unavailable.')
    return warnings


def evaluate(bundle, scan, correlations, *, now, config=EngineConfig()):
    people = {x.id: x for x in bundle.identities}
    accounts = {x.id: x for x in scan.identities}
    catalog = {x.id: x for x in bundle.entitlements}
    discovered = {x.id: x for x in scan.entitlements}
    policies = {(x.department, x.role): x for x in bundle.role_policies}
    candidates, binding_evidence = defaultdict(set), defaultdict(list)
    seen_bindings = set()
    for binding in correlations:
        if binding.account_id not in accounts or binding.identity_id not in people:
            raise InputError('Correlation references an unknown source account or HR identity')
        pair = (binding.account_id, binding.identity_id)
        if pair in seen_bindings:
            raise InputError('Duplicate correlation binding')
        seen_bindings.add(pair)
        candidates[binding.account_id].add(binding.identity_id)
        binding_evidence[binding.account_id].append(binding.model_dump())
    ambiguous_people = {p for ids in candidates.values() if len(ids) > 1 for p in ids}
    bound = {a: next(iter(ids)) for a, ids in candidates.items() if len(ids) == 1}
    grants, person_grants, person_accounts = defaultdict(list), defaultdict(set), defaultdict(set)
    for account_id, person_id in bound.items():
        person_accounts[person_id].add(account_id)
    for item in scan.assignments:
        grants[(item.identity, item.entitlement)].append(item.id)
        if item.identity in bound:
            person_grants[bound[item.identity]].add(item.entitlement)
    warnings = evidence_warnings(bundle, scan, now, config)
    actionable = not warnings
    findings = []

    def add(kind, account_id, entitlement_id, result, *, person_id=None, grant_ids=()):
        person_id = person_id or bound.get(account_id)
        person = people.get(person_id)
        account = accounts.get(account_id)
        authoritative, observed = catalog.get(entitlement_id), discovered.get(entitlement_id)
        sensitivity = authoritative.sensitivity if authoritative else observed.sensitivity if observed else 'unknown'
        privileged = authoritative.privileged if authoritative else observed.privileged if observed else None
        signals = [{'code': result, 'message': MESSAGES[result], 'points': POINTS[result]}]
        if observed and authoritative:
            if observed.sensitivity != authoritative.sensitivity or (observed.privileged is not None and observed.privileged != authoritative.privileged):
                signals.append({'code': 'catalog_mismatch', 'message': 'Source classification differs from policy; the more conservative classification is retained.', 'points': 10})
            if SENSITIVITY[observed.sensitivity] > SENSITIVITY[sensitivity]:
                sensitivity = observed.sensitivity
            privileged = privileged or bool(observed.privileged)
        if entitlement_id:
            signals.append({'code': 'sensitivity', 'message': f'Capability sensitivity: {sensitivity}.', 'points': SENSITIVITY[sensitivity]})
        if privileged:
            signals.append({'code': 'privileged', 'message': 'This capability is classified as elevated access.', 'points': 10})
        if account and not account.enabled and grant_ids:
            signals.append({'code': 'disabled_account_grants', 'message': 'The account is disabled but retained grants still exist.', 'points': 5})
        peer = {'available': False, 'count': 0, 'holders': 0, 'ratio': None, 'minimum': config.min_peer_count,
                'reason': 'Not applicable to this item.', 'group_by': ['department', 'role', 'employment_type']}
        if kind == 'assignment' and person and person.status == 'active':
            peers = [p for p in people.values() if p.id != person.id and p.status == 'active'
                     and (p.department, p.role, p.employment_type) == (person.department, person.role, person.employment_type)
                     and p.id in person_accounts and p.id not in ambiguous_people]
            holders = sum(entitlement_id in person_grants[p.id] for p in peers)
            peer.update(count=len(peers), holders=holders)
            if actionable and person.id not in ambiguous_people and len(peers) >= config.min_peer_count:
                ratio = holders / len(peers)
                peer.update(available=True, ratio=round(ratio, 4), reason='Distinct other active people with explicit source bindings.')
                if ratio < config.peer_rarity_threshold:
                    signals.append({'code': 'peer_rare', 'message': f'Access occurs in {holders} of {len(peers)} comparable peers; rarity alone is not a policy violation.', 'points': 10})
            else:
                peer['reason'] = ('Ambiguous linked-account coverage.' if person.id in ambiguous_people else 'Insufficient comparable peers.') if actionable else 'Evidence quality does not support peer inference.'
        score = min(100, sum(s['points'] for s in signals))
        if result in ('restricted', 'lifecycle_restricted', 'unauthorized_privilege'):
            recommendation = 'revoke'
        elif result in ('expected', 'permitted_privileged') and all(s['code'] not in ('catalog_mismatch', 'peer_rare', 'disabled_account_grants') for s in signals):
            recommendation = 'certify'
        else:
            recommendation = 'review' if kind == 'assignment' else 'acknowledge'
        if warnings:
            recommendation = 'review'
        findings.append({
            'key': digest([scan.source, kind, account_id, person_id, entitlement_id])[:32],
            'kind': kind, 'account_id': account_id, 'identity_id': person_id,
            'identity_name': person.name if person else account.username if account else 'Evidence coverage',
            'username': account.username if account else person.username if person else '',
            'department': person.department if person else 'unresolved', 'role': person.role if person else 'unresolved',
            'employment_status': person.status if person else 'unknown',
            'entitlement_id': entitlement_id,
            'entitlement_name': authoritative.name if authoritative else observed.name if observed else 'Account ownership' if kind == 'account' else 'Evidence quality',
            'source': scan.source, 'assignment_ids': sorted(grant_ids), 'sensitivity': sensitivity,
            'privileged': privileged, 'policy_result': result, 'signals': signals,
            'risk_score': score, 'risk_level': 'critical' if score >= 80 else 'high' if score >= 60 else 'medium' if score >= 30 else 'low',
            'recommendation': recommendation, 'peer': peer, 'actionable': actionable,
            'evidence': {'scan_id': scan.scan_id, 'scanned_at': scan.scanned_at, 'mapping_version': scan.mapping_version,
                         'snapshot_at': bundle.snapshot_at, 'policy_effective_from': bundle.effective_from,
                         'correlations': binding_evidence.get(account_id, []),
                         'linked_accounts': sorted(person_accounts.get(person_id, [])),
                         'policy_id': policies[(person.department, person.role)].id if person else None,
                         'warnings': warnings, 'engine_version': ENGINE_VERSION},
        })

    for (account_id, entitlement_id), grant_ids in sorted(grants.items()):
        person = people.get(bound.get(account_id))
        if len(candidates[account_id]) > 1:
            result = 'ambiguous'
        elif person is None:
            result = 'unmatched'
        elif person.status != 'active':
            result = 'lifecycle_restricted'
        elif entitlement_id not in catalog:
            result = 'unknown_entitlement'
        else:
            policy = policies[(person.department, person.role)]
            if entitlement_id in policy.restricted:
                result = 'restricted'
            elif entitlement_id in policy.expected:
                result = 'expected'
            elif entitlement_id in policy.privileged:
                result = 'permitted_privileged'
            elif catalog[entitlement_id].privileged or bool(discovered[entitlement_id].privileged):
                result = 'unauthorized_privilege'
            else:
                result = 'unlisted'
        add('assignment', account_id, entitlement_id, result, grant_ids=grant_ids)
    accounts_with_grants = {a for a, _ in grants}
    for account_id in sorted(accounts):
        if account_id not in bound and account_id not in accounts_with_grants:
            add('account', account_id, None, 'ambiguous' if candidates[account_id] else 'unmatched')
    if actionable:
        for person_id in sorted(person_accounts):
            person = people[person_id]
            if person.status == 'active' and person_id not in ambiguous_people:
                policy = policies[(person.department, person.role)]
                for entitlement_id in sorted(set(policy.expected) & set(scan.scope_entitlements) - person_grants[person_id]):
                    add('missing_access', None, entitlement_id, 'missing_expected', person_id=person_id)
    if warnings:
        add('coverage', None, None, 'coverage_gap')
    return {'findings': sorted(findings, key=lambda x: (-x['risk_score'], x['key'])),
            'warnings': warnings, 'actionable': actionable}
