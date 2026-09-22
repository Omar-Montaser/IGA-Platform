"""Build the demo campaign from a checked-in, normalized Module 3 fixture."""
from copy import deepcopy
from datetime import date, timedelta
from importlib.resources import files
import json
from uuid import uuid4

from iga_hr import validate_documents

from .domain import Scan, timestamp


def _fixture():
    path = files('iga_review').joinpath('fixtures/normalized-evidence.json')
    return json.loads(path.read_text(encoding='utf-8'))


def _node_kind(reference):
    if reference.startswith('role:business:'):
        return 'business_role'
    if reference.startswith('role:app:'):
        return 'application_role'
    if reference.startswith('group:'):
        return 'group'
    raise ValueError(f'Unsupported normalized grant-path reference: {reference}')


def build_demo(identities, policies, now):
    """Materialize stable fixture evidence with fresh envelope timestamps.

    Access observations, correlations, paths, justifications, and exceptions are
    loaded from the versioned fixture. Only time-dependent envelope fields are
    refreshed so repeated calls do not invent access from policy expectations.
    """
    identities, policies = deepcopy(identities), deepcopy(policies)
    delta = now.date() - date.fromisoformat(identities['snapshot_at'][:10])
    snapshot = now.date().isoformat() + 'T00:00:00Z'
    for document in (identities, policies):
        document.update(snapshot_at=snapshot, synthetic=True,
                        dataset_id='access-review-demo-' + now.date().isoformat())
    for person in identities['identities']:
        for field in ('start_date', 'end_date'):
            if person[field] is not None:
                person[field] = (date.fromisoformat(person[field]) + delta).isoformat()
    policies['effective_from'] = (date.fromisoformat(policies['effective_from']) + delta).isoformat()
    validate_documents(identities, policies)

    fixture = _fixture()
    source, observed_at = fixture['source'], timestamp(now)
    applications = [{**row, 'source': source} for row in fixture['applications']]
    accounts = [{**row, 'source': source} for row in fixture['accounts']]
    roles = [{**row, 'source': source} for row in fixture['roles']]
    groups = [{**row, 'source': source} for row in fixture['groups']]
    entitlements = [{**row, 'source': source} for row in fixture['entitlements']]

    grant_paths, assignments = [], []
    for access in fixture['access']:
        path_id = 'path:' + access['id']
        path = [{'kind': 'account', 'ref': access['account_id']}]
        path.extend({'kind': _node_kind(ref), 'ref': ref} for ref in access['via'])
        path.append({'kind': 'entitlement', 'ref': access['entitlement_id']})
        grant_paths.append({'id': path_id, 'account_id': access['account_id'],
                            'entitlement_id': access['entitlement_id'], 'source': source,
                            'grant_type': 'direct' if not access['via'] else 'inherited',
                            'path': path})
        assignments.append({'id': 'assignment:' + access['id'], 'identity': access['account_id'],
                            'entitlement': access['entitlement_id'], 'source': source,
                            'timestamp': observed_at, 'grant_path_ids': [path_id],
                            'business_justification': access.get('justification'),
                            'exception_id': access.get('exception_id')})

    exceptions = []
    for row in fixture['exceptions']:
        approved_at = now - timedelta(days=7)
        exceptions.append({key: value for key, value in row.items() if key != 'expires_after_days'} |
                          {'approved_at': timestamp(approved_at),
                           'expires_at': timestamp(now + timedelta(days=row['expires_after_days'])),
                           'source': source})
    history = []
    for row in fixture['history']:
        history.append({key: value for key, value in row.items() if key != 'days_ago'} |
                       {'occurred_at': timestamp(now - timedelta(days=row['days_ago'])),
                        'source': source})

    scan = {'schema_version': '2.0.0', 'scan_id': 'scan:' + str(uuid4()), 'source': source,
            'scanned_at': observed_at, 'complete': True,
            'mapping_version': fixture['mapping_version'],
            'scope_entitlements': [row['id'] for row in entitlements], 'request_id': None,
            'applications': applications, 'identities': accounts, 'roles': roles,
            'groups': groups, 'entitlements': entitlements, 'grant_paths': grant_paths,
            'assignments': assignments, 'exceptions': exceptions, 'history': history}
    Scan.model_validate(scan)
    return {'name': 'Workforce access review · Normalized synthetic fixture',
            'identities': identities, 'policies': policies,
            'correlations': deepcopy(fixture['correlations']), 'scan': scan}
