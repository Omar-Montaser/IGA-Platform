"""Immutable, source-independent context published by Module 1."""

from collections import Counter
from dataclasses import asdict, dataclass


@dataclass(frozen=True, slots=True)
class Identity:
    id: str
    username: str
    name: str
    department: str
    role: str
    status: str
    employment_type: str
    manager_id: str | None
    start_date: str
    end_date: str | None


@dataclass(frozen=True, slots=True)
class Entitlement:
    id: str
    name: str
    description: str
    type: str
    sensitivity: str
    privileged: bool


@dataclass(frozen=True, slots=True)
class RolePolicy:
    id: str
    department: str
    role: str
    expected: tuple[str, ...]
    restricted: tuple[str, ...]
    privileged: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class StatusRule:
    status: str
    access: str


@dataclass(frozen=True, slots=True)
class Bundle:
    schema_version: str
    dataset_id: str
    snapshot_at: str
    synthetic: bool
    effective_from: str
    unlisted_access: str
    identities: tuple[Identity, ...]
    entitlements: tuple[Entitlement, ...]
    role_policies: tuple[RolePolicy, ...]
    status_rules: tuple[StatusRule, ...]

    def identity_by_id(self, identity_id: str) -> Identity | None:
        return next((item for item in self.identities if item.id == identity_id), None)

    def identity_by_username(self, username: str) -> Identity | None:
        """Look up a canonical hint; this is not source-account correlation."""
        return next((item for item in self.identities if item.username == username), None)

    def policy_for(self, identity_id: str) -> RolePolicy:
        identity = self.identity_by_id(identity_id)
        if identity is None:
            raise KeyError(identity_id)
        return next(
            item for item in self.role_policies
            if (item.department, item.role) == (identity.department, identity.role)
        )

    def context_for(self, identity_id: str) -> dict:
        """Return independent JSON-ready context, never an access decision."""
        identity = self.identity_by_id(identity_id)
        if identity is None:
            raise KeyError(identity_id)
        policy = self.policy_for(identity_id)
        rule = next(item for item in self.status_rules if item.status == identity.status)
        policy_dict = asdict(policy)
        for field in ("expected", "restricted", "privileged"):
            policy_dict[field] = list(policy_dict[field])
        return {
            "identity": asdict(identity),
            "role_policy": policy_dict,
            "status_rule": asdict(rule),
        }

    def summary(self) -> dict:
        cohorts = Counter(
            (item.department, item.role) for item in self.identities if item.status == "active"
        )
        return {
            "schema_version": self.schema_version,
            "dataset_id": self.dataset_id,
            "snapshot_at": self.snapshot_at,
            "synthetic": self.synthetic,
            "identities": len(self.identities),
            "departments": len({item.department for item in self.identities}),
            "entitlements": len(self.entitlements),
            "role_policies": len(self.role_policies),
            "statuses": dict(sorted(Counter(item.status for item in self.identities).items())),
            "employment_types": dict(sorted(Counter(item.employment_type for item in self.identities).items())),
            "active_cohorts": [
                {"department": department, "role": role, "count": count}
                for (department, role), count in sorted(cohorts.items())
            ],
        }

