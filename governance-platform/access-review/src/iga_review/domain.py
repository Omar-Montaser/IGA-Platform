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


class Entitlement(Record):
    id: str
    name: str
    type: Literal['permission']
    sensitivity: Literal['low', 'medium', 'high', 'critical', 'unknown']
    privileged: bool | None
    source: str


class Assignment(Record):
    id: str
    identity: str
    entitlement: str
    source: str
    timestamp: str

    @field_validator('timestamp')
    @classmethod
    def valid_time(cls, value):
        instant(value)
        return value


class Scan(Record):
    schema_version: Literal['1.0.0']
    scan_id: str
    source: str
    scanned_at: str
    complete: bool
    mapping_version: str
    scope_entitlements: list[str]
    request_id: str | None
    identities: list[Account]
    entitlements: list[Entitlement]
    assignments: list[Assignment]

    @model_validator(mode='after')
    def consistent(self):
        time = instant(self.scanned_at)
        for collection in (self.identities, self.entitlements, self.assignments):
            if len({x.id for x in collection}) != len(collection):
                raise ValueError('Duplicate object ID')
            if any(x.source != self.source for x in collection):
                raise ValueError('All objects must belong to scan.source')
        accounts = {x.id for x in self.identities}
        entitlements = {x.id for x in self.entitlements}
        if len(set(self.scope_entitlements)) != len(self.scope_entitlements) or set(self.scope_entitlements) != entitlements:
            raise ValueError('Scope must contain each declared entitlement exactly once')
        for item in self.assignments:
            if item.identity not in accounts or item.entitlement not in entitlements:
                raise ValueError('Assignment references an unknown account or entitlement')
            if instant(item.timestamp) > time:
                raise ValueError('Assignment timestamp is after scan time')
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
