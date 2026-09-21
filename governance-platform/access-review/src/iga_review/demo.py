"""Synthetic integration input; never represents observed access on a real host."""
from copy import deepcopy
from datetime import date, timedelta
from uuid import uuid4
from iga_hr import validate_documents
from .domain import canonical, timestamp


def build_demo(identities, policies, now):
    identities, policies = deepcopy(identities), deepcopy(policies)
    delta = now.date() - date.fromisoformat(identities['snapshot_at'][:10])
    snapshot = now.date().isoformat() + 'T00:00:00Z'
    for doc in (identities, policies):
        doc.update(snapshot_at=snapshot, synthetic=True, dataset_id='access-review-demo-' + now.date().isoformat())
    for person in identities['identities']:
        for field in ('start_date', 'end_date'):
            if person[field] is not None:
                person[field] = (date.fromisoformat(person[field]) + delta).isoformat()
    policies['effective_from'] = (date.fromisoformat(policies['effective_from']) + delta).isoformat()
    bundle = validate_documents(identities, policies)
    source, at = 'prototype-system', timestamp(now)
    accounts, grants, correlations = [], [], []
    def grant(account, ent, suffix=''):
        grants.append({'id': f'grant:{account}:{ent}{suffix}', 'identity': account, 'entitlement': ent, 'source': source, 'timestamp': at})
    for person in bundle.identities:
        account = 'acct:' + person.id.removeprefix('id:')
        accounts.append({'id': account, 'username': person.username, 'enabled': person.status in ('active', 'on_leave'), 'source': source})
        correlations.append({'account_id': account, 'identity_id': person.id, 'evidence': 'Explicit synthetic fixture binding; no username inference.'})
        expected = bundle.policy_for(person.id).expected
        for ent in expected if person.status == 'active' else expected[:2]:
            grant(account, ent)
    # Missing baseline, explicit violation through two grant paths, and a rare capability.
    grants = [g for g in grants if not (g['identity'] == 'acct:person-0003' and g['entitlement'] == 'ent:engineering:source-write')]
    grant('acct:person-0005', 'ent:engineering:production-deploy', ':direct')
    grant('acct:person-0005', 'ent:engineering:production-deploy', ':inherited')
    grant('acct:person-0006', 'ent:security:audit-read')
    grant('acct:person-0013', 'ent:finance:ledger-admin')
    # A second account stays distinct while baseline checks use the HR person's union.
    accounts.append({'id': 'acct:secondary', 'username': 'secondary.account', 'enabled': True, 'source': source})
    correlations.append({'account_id': 'acct:secondary', 'identity_id': 'id:person-0004', 'evidence': 'Explicit secondary fixture account.'})
    grant('acct:secondary', 'ent:engineering:source-write')
    for account, username in (('acct:unknown', 'unmatched.account'), ('acct:empty', 'unowned.empty'), ('acct:ambiguous', 'shared.login')):
        accounts.append({'id': account, 'username': username, 'enabled': True, 'source': source})
    grant('acct:unknown', 'ent:collaboration:workspace-read')
    for identity in ('id:person-0001', 'id:person-0013'):
        correlations.append({'account_id': 'acct:ambiguous', 'identity_id': identity, 'evidence': 'Conflicting fixture ownership claim requiring review.'})
    entitlements = [{'id': e.id, 'name': e.name, 'type': e.type, 'sensitivity': e.sensitivity, 'privileged': e.privileged, 'source': source} for e in bundle.entitlements]
    entitlements.append({'id': 'ent:unmapped:capability', 'name': 'Unmapped application capability', 'type': 'permission', 'sensitivity': 'unknown', 'privileged': None, 'source': source})
    grant('acct:person-0007', 'ent:unmapped:capability')
    return {'name': 'Workforce access review · Synthetic demo', 'identities': identities, 'policies': policies,
            'correlations': correlations, 'scan': {'schema_version': '1.0.0', 'scan_id': 'scan:' + str(uuid4()),
              'source': source, 'scanned_at': at, 'complete': True, 'mapping_version': 'demo-mapping-1',
              'scope_entitlements': [e['id'] for e in entitlements], 'request_id': None,
              'identities': accounts, 'entitlements': entitlements, 'assignments': grants}}
