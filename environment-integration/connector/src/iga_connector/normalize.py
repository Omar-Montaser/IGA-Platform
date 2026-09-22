"""The normalization boundary.

Linux vocabulary enters this module and generic objects leave it. Nothing above
Module 3 ever sees a POSIX group name or a sudoers file path.

The scan document shape is fixed by Module 4's contract (docs/contract.md) and
enforced by their pydantic model (iga_review/domain.py), which sets
``extra='forbid'`` and ``strict=True``. Three consequences drive this module:

* unknown fields are rejected, so we emit exactly the declared keys;
* nothing is coerced, so booleans must be real booleans;
* a nullable field has no default, so it must be PRESENT as ``null``.

Schema v2 additionally asks *how* access was reached, not only that it is held.
That is `grant_paths`, and it is the one place where the native representation
is visible in the output shape rather than the vocabulary: a POSIX group
membership is an inherited two-hop path, a sudoers drop-in is a direct one-hop
path. Same generic entitlement, different route.
"""
from datetime import datetime, timezone
from uuid import uuid4

SCHEMA_VERSION = "2.0.0"


def _ts(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _now():
    return datetime.now(timezone.utc)


# --------------------------------------------------------------- identifiers
# Every generic ID is minted here and nowhere else. remediation.py imports these
# helpers rather than rebuilding the strings: if the two modules formatted IDs
# independently they could drift, and the approved-target check below would then
# reject valid requests for a reason no one could see.
def account_id(source, uid):
    """Immutable native account identifier, per the Module 1 handoff guidance."""
    return f"{source}:uid:{uid}"


def application_id(source):
    return f"{source}:app:linux"


def group_id(source, native_group):
    return f"{source}:group:{native_group}"


def assignment_id(source, uid, entitlement):
    return f"{source}:grant:{uid}:{entitlement}"


def group_path_id(source, uid, native_group):
    return f"{source}:path:{uid}:group:{native_group}"


def sudo_path_id(source, uid):
    return f"{source}:path:{uid}:sudo"


class Mapping:
    """Native <-> generic entitlement translation. Module 3 owns this."""

    def __init__(self, document):
        self.version = document["mapping_version"]
        self.source = document["source"]
        self.entries = document["entitlements"]
        self._group_to_ent = {
            e["native_id"]: eid for eid, e in self.entries.items()
            if e["native_type"] == "posix_group"
        }
        self._sudo_ents = [eid for eid, e in self.entries.items()
                           if e["native_type"] == "sudo"]

    @property
    def scope(self):
        return sorted(self.entries)

    @property
    def managed_groups(self):
        return sorted(self._group_to_ent)

    def entitlement_for_group(self, group):
        return self._group_to_ent.get(group)

    @property
    def sudo_entitlement(self):
        return self._sudo_ents[0] if self._sudo_ents else None

    def native_for(self, entitlement_id):
        return self.entries.get(entitlement_id)


class Route:
    """One way a native account reaches one generic entitlement."""

    __slots__ = ("path_id", "grant_type", "native_group", "evidence")

    def __init__(self, path_id, grant_type, native_group, evidence):
        self.path_id = path_id
        self.grant_type = grant_type
        self.native_group = native_group
        self.evidence = evidence


def held_entitlements(account, mapping, source):
    """Generic entitlements this native account holds, with their grant routes.

    Returns ``{entitlement_id: [Route, ...]}``. Shared by the scan builder and
    by remediation's approved-target check, so both compute the same IDs from
    the same live reading and cannot disagree.
    """
    held = {}
    for native in account.groups:
        eid = mapping.entitlement_for_group(native)
        if eid is None:
            continue
        held.setdefault(eid, []).append(Route(
            group_path_id(source, account.uid, native),
            "inherited", native, "/etc/group"))
    if account.sudo_lines and mapping.sudo_entitlement:
        held.setdefault(mapping.sudo_entitlement, []).append(Route(
            sudo_path_id(source, account.uid),
            "direct", None, f"/etc/sudoers.d/90-iga-{account.username}"))
    return held


def build_scan(accounts, mapping, *, mtimes=None, source, request_id=None,
               complete=True, now=None, service_accounts=()):
    mtimes = mtimes or {}
    scanned = now or _now()
    # Sub-second precision is required, not cosmetic. Module 4 rejects a
    # verification scan whose scanned_at is <= the approval it verifies
    # (service.py::_verification_problem). Truncating to whole seconds makes a
    # scan taken moments after an approval in the same second compare as
    # earlier, and the verification fails intermittently - most likely during a
    # fast demo. Their `instant()` accepts 1-6 fractional digits.
    scanned_at = scanned.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    ceiling = scanned.timestamp()
    service = set(service_accounts)
    app = application_id(source)

    def grant_time(path):
        """Linux records no grant time. The modification time of the file that
        carries the grant is the best available evidence; never after the scan."""
        return _ts(min(mtimes.get(path, ceiling), ceiling))

    # One application. The target is a single host, and the department prefix
    # inside an entitlement ID is Module 1's vocabulary, not an application
    # boundary this connector can observe.
    applications = [{
        "id": app,
        "name": "Linux host",
        "criticality": "unknown",
        "source": source,
    }]

    # A POSIX group becomes a generic group node so that grant paths can pass
    # through it. `privileged` is a required bool here, unlike the entitlement's
    # nullable one - see the limitations note in the README.
    groups = [{
        "id": group_id(source, native),
        "name": native,
        "application_id": app,
        "privileged": False,
        "source": source,
    } for native in mapping.managed_groups]

    identities, grant_paths, assignments = [], [], []

    for acc in accounts:
        aid = account_id(source, acc.uid)
        identities.append({
            "id": aid,
            "username": acc.username,
            "enabled": acc.enabled,
            "source": source,
            "application_id": app,
            # POSIX records no account-type attribute. The service accounts are
            # named in connector configuration; everything else above the system
            # UID floor is treated as human. Stated as a limitation rather than
            # dressed up as discovery.
            "account_type": "service" if acc.username in service else "human",
        })

        for eid, routes in held_entitlements(acc, mapping, source).items():
            for route in routes:
                # A group membership is a two-hop inherited path; a sudoers
                # drop-in is a one-hop direct path. Their validator enforces
                # that correspondence, so it cannot silently rot.
                hops = [{"kind": "account", "ref": aid}]
                if route.native_group is not None:
                    hops.append({"kind": "group",
                                 "ref": group_id(source, route.native_group)})
                hops.append({"kind": "entitlement", "ref": eid})
                grant_paths.append({
                    "id": route.path_id,
                    "account_id": aid,
                    "entitlement_id": eid,
                    "source": source,
                    "grant_type": route.grant_type,
                    "path": hops,
                })

            # One assignment per account+entitlement, citing every route that
            # carries it. Two groups mapping to one entitlement is a single
            # assignment with two grant paths, not two assignments.
            assignments.append({
                "id": assignment_id(source, acc.uid, eid),
                "identity": aid,
                "entitlement": eid,
                "source": source,
                "timestamp": min(grant_time(r.evidence) for r in routes),
                "grant_path_ids": [r.path_id for r in routes],
                # Linux carries neither of these. Present as null, not omitted.
                "business_justification": None,
                "exception_id": None,
            })

    entitlements = []
    for eid in mapping.scope:
        native = mapping.entries[eid]
        entitlements.append({
            "id": eid,
            "name": f"{native['native_type']} {native['native_id']}",
            "type": "permission",
            # The connector observes access; it does not classify business
            # sensitivity. Module 1's catalog is authoritative, and the contract
            # accepts 'unknown'/null here rather than inviting a second opinion.
            "sensitivity": "unknown",
            "privileged": None,
            "source": source,
            "application_id": app,
        })

    return {
        "schema_version": SCHEMA_VERSION,
        "scan_id": f"scan:{uuid4()}",
        "source": source,
        "scanned_at": scanned_at,
        "complete": complete,
        "mapping_version": mapping.version,
        "scope_entitlements": mapping.scope,
        "request_id": request_id,
        "applications": applications,
        "identities": identities,
        # Linux has no role layer between an account and a group. Empty is the
        # honest answer; the collection is required, so it is present.
        "roles": [],
        "groups": groups,
        "entitlements": entitlements,
        "grant_paths": grant_paths,
        "assignments": assignments,
        # The target records neither approved exceptions nor grant history.
        "exceptions": [],
        "history": [],
    }
