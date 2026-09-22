"""Source-independent scan, principal, and review contracts."""
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def utcnow():
    return datetime.now(timezone.utc)


def timestamp(value):
    return value.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')


def instant(value):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z', value):
        raise ValueError('Expected a UTC timestamp ending in Z')
    return datetime.fromisoformat(value)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def strict_json(raw):
    try:
        if isinstance(raw, bytes):
            raw = raw.decode('utf-8')
        if not isinstance(raw, str) or len(raw.encode('utf-8')) > 10 * 1024 * 1024:
            raise InputError('JSON exceeds the 10 MiB limit')
        depth, quoted, escaped = 0, False, False
        for char in raw:
            if quoted:
                if escaped:
                    escaped = False
                elif char == chr(92):
                    escaped = True
                elif char == chr(34):
                    quoted = False
            elif char == chr(34):
                quoted = True
            elif char in '[{':
                depth += 1
                if depth > 64:
                    raise InputError('JSON exceeds 64 nesting levels')
            elif char in ']}':
                depth -= 1
    except UnicodeError as exc:
        raise InputError('JSON must be valid UTF-8') from exc
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise InputError('Duplicate JSON key')
            result[key] = value
        return result
    def constant(value):
        raise InputError('Non-finite JSON number')
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, RecursionError, UnicodeError) as exc:
        raise InputError('Invalid or excessively nested JSON') from exc


class InputError(ValueError):
    pass


class Record(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)

    @field_validator('*', mode='before')
    @classmethod
    def clean_strings(cls, value):
        if isinstance(value, str):
            if not value or value.strip() != value or len(value) > 2000:
                raise ValueError('Strings must be nonempty, trimmed and at most 2000 characters')
            if any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in value):
                raise ValueError('Control characters and unpaired surrogates are invalid')
        return value


class Account(Record):
    id: str
    username: str
    enabled: bool
    source: str
    application_id: str
    account_type: Literal['human', 'service', 'shared', 'privileged', 'unknown']


class Application(Record):
    id: str
    name: str
    criticality: Literal['low', 'medium', 'high', 'critical', 'unknown']
    source: str


class AccessRole(Record):
    id: str
    name: str
    kind: Literal['business', 'application']
    application_id: str | None
    privileged: bool
    source: str


class Group(Record):
    id: str
    name: str
    application_id: str
    privileged: bool
    source: str


class Entitlement(Record):
    id: str
    name: str
    type: Literal['permission']
    sensitivity: Literal['low', 'medium', 'high', 'critical', 'unknown']
    privileged: bool | None
    source: str
    application_id: str


class GrantNode(Record):
    kind: Literal['account', 'business_role', 'application_role', 'group', 'entitlement']
    ref: str


class GrantPath(Record):
    id: str
    account_id: str
    entitlement_id: str
    source: str
    grant_type: Literal['direct', 'inherited']
    path: list[GrantNode] = Field(min_length=2)


class ApprovedException(Record):
    id: str
    account_id: str
    entitlement_id: str
    approved_by: str
    approved_at: str
    expires_at: str | None
    reason: str
    source: str

    @field_validator('approved_at', 'expires_at')
    @classmethod
    def valid_time(cls, value):
        if value is not None:
            instant(value)
        return value


class AccessHistory(Record):
    id: str
    account_id: str
    entitlement_id: str | None
    event: Literal['granted', 'revoked', 'changed', 'reviewed']
    occurred_at: str
    detail: str
    source: str

    @field_validator('occurred_at')
    @classmethod
    def valid_time(cls, value):
        instant(value)
        return value


class Assignment(Record):
    id: str
    identity: str
    entitlement: str
    source: str
    timestamp: str
    grant_path_ids: list[str] = Field(min_length=1)
    business_justification: str | None
    exception_id: str | None

    @field_validator('timestamp')
    @classmethod
    def valid_time(cls, value):
        instant(value)
        return value


class Scan(Record):
    schema_version: Literal['2.0.0']
    scan_id: str
    source: str
    scanned_at: str
    complete: bool
    mapping_version: str
    scope_entitlements: list[str]
    request_id: str | None
    applications: list[Application]
    identities: list[Account]
    roles: list[AccessRole]
    groups: list[Group]
    entitlements: list[Entitlement]
    grant_paths: list[GrantPath]
    assignments: list[Assignment]
    exceptions: list[ApprovedException]
    history: list[AccessHistory]

    @model_validator(mode='after')
    def consistent(self):
        time = instant(self.scanned_at)
        collections = (self.applications, self.identities, self.roles, self.groups,
                       self.entitlements, self.grant_paths, self.assignments,
                       self.exceptions, self.history)
        for collection in collections:
            if len({x.id for x in collection}) != len(collection):
                raise ValueError('Duplicate object ID')
            if any(x.source != self.source for x in collection):
                raise ValueError('All objects must belong to scan.source')
        applications = {x.id for x in self.applications}
        accounts = {x.id for x in self.identities}
        entitlements = {x.id for x in self.entitlements}
        roles = {x.id: x for x in self.roles}
        groups = {x.id for x in self.groups}
        paths = {x.id: x for x in self.grant_paths}
        exceptions = {x.id: x for x in self.exceptions}
        if len(set(self.scope_entitlements)) != len(self.scope_entitlements) or set(self.scope_entitlements) != entitlements:
            raise ValueError('Scope must contain each declared entitlement exactly once')
        if any(x.application_id not in applications for x in self.identities):
            raise ValueError('Account references an unknown application')
        if any(x.application_id not in applications for x in self.entitlements):
            raise ValueError('Entitlement references an unknown application')
        if any(x.application_id not in applications for x in self.groups):
            raise ValueError('Group references an unknown application')
        for role in self.roles:
            if role.kind == 'application' and role.application_id not in applications:
                raise ValueError('Application role references an unknown application')
            if role.kind == 'business' and role.application_id is not None:
                raise ValueError('Business role cannot belong to one application')
        node_sets = {
            'account': accounts,
            'business_role': {x.id for x in roles.values() if x.kind == 'business'},
            'application_role': {x.id for x in roles.values() if x.kind == 'application'},
            'group': groups,
            'entitlement': entitlements,
        }
        for path in self.grant_paths:
            if path.account_id not in accounts or path.entitlement_id not in entitlements:
                raise ValueError('Grant path references an unknown account or entitlement')
            if path.path[0] != GrantNode(kind='account', ref=path.account_id):
                raise ValueError('Grant path must start with its account')
            if path.path[-1] != GrantNode(kind='entitlement', ref=path.entitlement_id):
                raise ValueError('Grant path must end with its entitlement')
            if (path.grant_type == 'direct') != (len(path.path) == 2):
                raise ValueError('Direct paths contain no intermediate role or group')
            if any(node.ref not in node_sets[node.kind] for node in path.path):
                raise ValueError('Grant path contains an unknown node reference')
        for item in self.assignments:
            if item.identity not in accounts or item.entitlement not in entitlements:
                raise ValueError('Assignment references an unknown account or entitlement')
            if instant(item.timestamp) > time:
                raise ValueError('Assignment timestamp is after scan time')
            if len(set(item.grant_path_ids)) != len(item.grant_path_ids):
                raise ValueError('Assignment grant paths must be unique')
            for path_id in item.grant_path_ids:
                path = paths.get(path_id)
                if path is None or (path.account_id, path.entitlement_id) != (item.identity, item.entitlement):
                    raise ValueError('Assignment references a mismatched grant path')
            if item.exception_id is not None:
                exception = exceptions.get(item.exception_id)
                if exception is None or (exception.account_id, exception.entitlement_id) != (item.identity, item.entitlement):
                    raise ValueError('Assignment references a mismatched exception')
        for exception in self.exceptions:
            if exception.account_id not in accounts or exception.entitlement_id not in entitlements:
                raise ValueError('Exception references an unknown account or entitlement')
            if instant(exception.approved_at) > time:
                raise ValueError('Exception approval is after scan time')
            if exception.expires_at is not None and instant(exception.expires_at) <= instant(exception.approved_at):
                raise ValueError('Exception expiry must follow approval')
        for event in self.history:
            if event.account_id not in accounts or (event.entitlement_id is not None and event.entitlement_id not in entitlements):
                raise ValueError('History references an unknown account or entitlement')
            if instant(event.occurred_at) > time:
                raise ValueError('History event is after scan time')
        return self


class Correlation(Record):
    account_id: str
    identity_id: str
    evidence: str


class CampaignInput(Record):
    name: str
    identities: dict
    policies: dict
    scan: Scan
    correlations: list[Correlation]


class DecisionInput(Record):
    action: Literal['certify', 'revoke', 'acknowledge']
    reason: str = Field(min_length=8, max_length=2000)
    expected_version: int = Field(ge=1)
    acknowledge_risk: bool = False


@dataclass(frozen=True)
class EngineConfig:
    max_hr_age_days: int = 30
    max_scan_age_hours: int = 24
    max_clock_skew_seconds: int = 300
    min_peer_count: int = 5
    peer_rarity_threshold: float = 0.2

    def __post_init__(self):
        if min(self.max_hr_age_days, self.max_scan_age_hours, self.min_peer_count) <= 0 or self.max_clock_skew_seconds < 0 or not 0 <= self.peer_rarity_threshold <= 1:
            raise ValueError('Invalid engine configuration')


@dataclass(frozen=True)
class User:
    id: str
    name: str
    role: str
    hr_identity_id: str | None
    token_hash: str

    def public(self):
        return {'id': self.id, 'name': self.name, 'role': self.role, 'hr_identity_id': self.hr_identity_id}
