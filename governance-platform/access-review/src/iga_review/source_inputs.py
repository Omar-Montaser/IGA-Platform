"""Server-managed input files and optional source-specific correlation checks."""
from copy import deepcopy
from datetime import date
from pathlib import Path
import re

from iga_hr import validate_documents
from .domain import InputError, strict_json


class SourceInputs:
    def __init__(self, directory, settings=None, *, demo=False):
        self.directory, self.settings, self.demo = Path(directory), settings or {}, demo

    def read(self, reference):
        # References originate only in administrator-managed server configuration.
        return strict_json((self.directory / reference).read_text(encoding='utf-8'))

    def __call__(self, now):
        if self.demo:
            raw = (self.directory / 'demo-import.json').read_bytes()
            try:
                payload = strict_json(raw)
            except InputError:
                # Earlier Windows demo initialization used the system encoding.
                # Compatibility is limited to this server-created synthetic file.
                payload = strict_json(raw.decode('cp1252'))
            docs = {key: deepcopy(payload[key]) for key in ('identities', 'policies', 'correlations')}
            if not docs['identities'].get('synthetic') or not docs['policies'].get('synthetic'):
                raise InputError('Demo context must be synthetic.')
            # Rebase synthetic HR context only. Never rebuild the persistent source
            # or restore fixture assignments removed by an earlier decision.
            original = date.fromisoformat(docs['identities']['snapshot_at'][:10])
            delta = now.date() - original
            for key in ('identities', 'policies'):
                docs[key]['snapshot_at'] = now.date().isoformat() + 'T00:00:00Z'
            for person in docs['identities']['identities']:
                for key in ('start_date', 'end_date'):
                    if person[key]:
                        person[key] = (date.fromisoformat(person[key]) + delta).isoformat()
            docs['policies']['effective_from'] = (date.fromisoformat(docs['policies']['effective_from']) + delta).isoformat()
        else:
            docs = {key: self.read(self.settings[key]) for key in ('identities', 'policies', 'correlations')}
            if isinstance(docs['correlations'], dict):
                docs['correlations'] = docs['correlations']['correlations']
        validate_documents(docs['identities'], docs['policies'])
        return docs


def validate_binding_evidence(scan, correlations, mode=None):
    """Cross-check an explicit binding, never infer ownership from a username.

    The POSIX capture writer includes this evidence in existing lab exports.
    Also detect that format for legacy configurations that lack a declared mode.
    """
    accounts = {a.id: a.username for a in scan.identities}
    for row in correlations:
        match = re.search(r'POSIX account (\S+) \(uid (\d+)\)', row.get('evidence', ''))
        if mode == 'linux-posix' and row['account_id'] in accounts and not match:
            raise InputError('Linux correlations need captured username evidence; refresh the correlation file.')
        if match and row['account_id'] in accounts and match[1] != accounts[row['account_id']]:
            raise InputError('Correlation evidence names a different account. Refresh the source correlation file.')
        if match and row['account_id'] in accounts and row['account_id'] != f'{scan.source}:uid:{match[2]}':
            raise InputError('Correlation UID evidence differs from the source account ID. Refresh the source correlation file.')
