"""Deterministic policy facts and safety constraints; no access verdicts."""
from dataclasses import asdict
from collections import defaultdict
from datetime import datetime, timezone
from .domain import EngineConfig, InputError, digest, instant

ENGINE_VERSION = '2.2.0'
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
    assignments = {x.id: x for x in scan.assignments}
    paths = {x.id: x for x in scan.grant_paths}
    applications = {x.id: x for x in scan.applications}
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
            if (observed.sensitivity != 'unknown' and observed.sensitivity != authoritative.sensitivity) or (observed.privileged is not None and observed.privileged != authoritative.privileged):
                signals.append({'code': 'catalog_mismatch', 'message': 'Source classification differs from policy; the more conservative classification is retained.', 'points': 10})
            if observed.sensitivity != 'unknown' and SENSITIVITY[observed.sensitivity] > SENSITIVITY[sensitivity]:
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
        policy = policies.get((person.department, person.role)) if person else None
        policy_id = policy.id if policy else 'unresolved-policy'
        person_status = person.status if person else 'unknown'
        policy_text = {
            'expected': f'{entitlement_id} is expected for role policy {policy_id}.',
            'permitted_privileged': f'{entitlement_id} is listed as optional privileged access by role policy {policy_id}.',
            'restricted': f'{entitlement_id} is explicitly restricted by role policy {policy_id}.',
            'lifecycle_restricted': f'Lifecycle rule for status {person_status} permits no access.',
            'unauthorized_privilege': f'{entitlement_id} is privileged but is not permitted by role policy {policy_id}.',
            'unlisted': f'{entitlement_id} is not listed by role policy {policy_id}; unlisted access requires review.',
            'unknown_entitlement': f'{entitlement_id} is absent from the authoritative policy catalog.',
            'unmatched': 'No supplied correlation binds this source account to an HR identity.',
            'ambiguous': 'More than one supplied correlation claims this source account.',
            'missing_expected': f'{entitlement_id} is expected by role policy {policy_id} but was not observed in complete scope.',
            'coverage_gap': 'Evidence quality rules block decisions until complete, fresh evidence is supplied.',
        }[result]
        constraints = []
        if warnings:
            constraints.append({'code': 'evidence_not_actionable', 'effect': 'decision_blocked',
                                'required_action': None, 'text': 'No access decision may execute against stale or incomplete evidence.'})
        if result in ('restricted', 'lifecycle_restricted', 'unauthorized_privilege'):
            constraints.append({'code': 'hard_policy_remove', 'effect': 'non_discretionary',
                                'required_action': 'remove', 'text': policy_text})
        if result in ('unmatched', 'ambiguous'):
            constraints.append({'code': 'ownership_unresolved', 'effect': 'decision_blocked',
                                'required_action': 'investigate', 'text': 'Resolve account ownership before changing access.'})
        if privileged:
            constraints.append({'code': 'privileged_human_review', 'effect': 'mandatory_human_review',
                                'required_action': None, 'text': 'Privileged access must never be silently auto-certified.'})
        assignment_rows = [assignments[item_id] for item_id in grant_ids]
        path_ids = sorted({path_id for row in assignment_rows for path_id in row.grant_path_ids})
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
            'peer': peer, 'actionable': actionable, 'constraints': constraints,
            'policy_fact': {'code': result, 'rule_id': policy.id if policy else result,
                            'text': policy_text},
            'grant_path_ids': path_ids,
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
    findings = sorted(findings, key=lambda x: (-x['risk_score'], x['key']))
    grouped = defaultdict(list)
    for item in findings:
        owner = item['identity_id'] or ('account:' + item['account_id'] if item['account_id'] else 'system')
        grouped[owner].append(item)
    cases = []
    for owner, items in sorted(grouped.items()):
        person_id = items[0]['identity_id']
        account_ids = sorted({item['account_id'] for item in items if item['account_id']} |
                             set(person_accounts.get(person_id, ())))
        item_entitlements = {item['entitlement_id'] for item in items if item['entitlement_id']}
        case_assignments = [row for row in scan.assignments
                            if row.identity in account_ids and row.entitlement in item_entitlements]
        case_path_ids = {path_id for row in case_assignments for path_id in row.grant_path_ids}
        case_paths = [path.model_dump() for path_id, path in paths.items() if path_id in case_path_ids]
        role_ids = {node['ref'] for path in case_paths for node in path['path']
                    if node['kind'] in ('business_role', 'application_role')}
        group_ids = {node['ref'] for path in case_paths for node in path['path'] if node['kind'] == 'group'}
        case_roles = [row.model_dump() for row in scan.roles if row.id in role_ids]
        case_groups = [row.model_dump() for row in scan.groups if row.id in group_ids]
        case_exceptions = [row.model_dump() for row in scan.exceptions
                           if row.account_id in account_ids and row.entitlement_id in item_entitlements]
        case_history = [row.model_dump() for row in scan.history
                        if row.account_id in account_ids and (row.entitlement_id is None or row.entitlement_id in item_entitlements)]
        application_ids = {accounts[account_id].application_id for account_id in account_ids}
        application_ids |= {discovered[entitlement_id].application_id for entitlement_id in item_entitlements
                            if entitlement_id in discovered}
        evidence_refs = ([f'identity:{person_id}'] if person_id else []) + [f'account:{x}' for x in account_ids]
        evidence_refs += [f'item:{item["key"]}' for item in items]
        evidence_refs += [f'path:{x}' for x in sorted(case_path_ids)]
        evidence_refs += [f'application:{x}' for x in sorted(application_ids)]
        evidence_refs += [f'entitlement:{x}' for x in sorted(item_entitlements)]
        evidence_refs += [f'assignment:{row.id}' for row in case_assignments]
        for kind, rows in (('role', case_roles), ('group', case_groups),
                           ('exception', case_exceptions), ('history', case_history)):
            evidence_refs += [f'{kind}:{row["id"]}' for row in rows]
        evidence_refs.append(f'scan:{scan.scan_id}')
        gaps = []
        if case_assignments:
            gaps.append('Usage/last-used telemetry is not part of this scan contract; do not infer inactivity.')
            if any(row.business_justification is None for row in case_assignments):
                gaps.append('Business justification is missing for one or more assignments.')
            if any(row.timestamp is None for row in case_assignments):
                gaps.append('Grant time is unknown for one or more assignments; scan time is not grant time.')
            if not case_history:
                gaps.append('No access history was supplied; this does not establish that access was never used or reviewed.')
        cases.append({
            'key': digest([scan.source, 'case', owner])[:32],
            'identity_id': person_id,
            'review_context': {'reviewed_at': now.isoformat(), 'scanned_at': scan.scanned_at,
                               'source': scan.source, 'scan_id': scan.scan_id,
                               'complete': scan.complete, 'mapping_version': scan.mapping_version},
            'identity_context': bundle.context_for(person_id) if person_id else None,
            'accounts': [accounts[x].model_dump() for x in account_ids],
            'applications': [applications[x].model_dump() for x in sorted(application_ids)],
            'items': items,
            'assignments': [row.model_dump() for row in case_assignments],
            'grant_paths': case_paths,
            'roles': case_roles,
            'groups': case_groups,
            'exceptions': case_exceptions,
            'history': case_history,
            'relevant_entitlements': [asdict(catalog[x]) if x in catalog else discovered[x].model_dump()
                                      for x in sorted(item_entitlements)],
            'evidence_refs': evidence_refs,
            'warnings': warnings,
            'evidence_gaps': gaps,
        })
    return {'cases': cases, 'findings': findings, 'warnings': warnings, 'actionable': actionable}
