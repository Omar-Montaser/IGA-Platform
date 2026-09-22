"""The normalization boundary.

Linux vocabulary enters this module and generic objects leave it. Nothing above
Module 3 ever sees a POSIX group name or a sudoers file path.

The scan document shape is fixed by Module 4's contract (docs/contract.md):
unknown fields are rejected, so this module emits exactly the declared keys.
"""
import os
from datetime import datetime, timezone
from uuid import uuid4


def _ts(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _now():
    return datetime.now(timezone.utc)


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


def account_id(source, uid):
    """Immutable native account identifier, per the Module 1 handoff guidance."""
    return f"{source}:uid:{uid}"


def build_scan(accounts, mapping, *, mtimes=None, source, request_id=None,
               complete=True, now=None):
    mtimes = mtimes or {}
    scanned = now or _now()
    scanned_at = scanned.strftime("%Y-%m-%dT%H:%M:%SZ")
    ceiling = scanned.timestamp()

    def grant_time(path):
        """Linux records no grant time. The modification time of the file that
        carries the grant is the best available evidence; never after the scan."""
        return _ts(min(mtimes.get(path, ceiling), ceiling))

    identities, assignments = [], []
    for acc in accounts:
        aid = account_id(source, acc.uid)
        identities.append({
            "id": aid,
            "username": acc.username,
            "enabled": acc.enabled,
            "source": source,
        })

        for group in acc.groups:
            eid = mapping.entitlement_for_group(group)
            if eid is None:
                continue
            assignments.append({
                "id": f"{source}:grant:{acc.uid}:{group}",
                "identity": aid,
                "entitlement": eid,
                "source": source,
                "timestamp": grant_time("/etc/group"),
            })

        if acc.sudo_lines and mapping.sudo_entitlement:
            path = f"/etc/sudoers.d/90-iga-{acc.username}"
            assignments.append({
                "id": f"{source}:grant:{acc.uid}:sudo",
                "identity": aid,
                "entitlement": mapping.sudo_entitlement,
                "source": source,
                "timestamp": grant_time(path),
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
        })

    return {
        "schema_version": "1.0.0",
        "scan_id": f"scan:{uuid4()}",
        "source": source,
        "scanned_at": scanned_at,
        "complete": complete,
        "mapping_version": mapping.version,
        "scope_entitlements": mapping.scope,
        "request_id": request_id,
        "identities": identities,
        "entitlements": entitlements,
        "assignments": assignments,
    }
