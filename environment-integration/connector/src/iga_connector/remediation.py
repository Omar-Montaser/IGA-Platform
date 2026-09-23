"""Approved removal, translated back into a native operation.

Every change goes through /usr/local/sbin/iga-remediate, which enforces the
guards (system accounts, the service account, primary groups, unmanaged groups,
sudoers validity). This module never runs gpasswd or edits sudoers itself, so
the guard set cannot be bypassed by a bug here.
"""
import json

from . import discovery, normalize

REMEDIATE = "/usr/local/sbin/iga-remediate"


class RemediationError(RuntimeError):
    pass


def _uid_from_account_id(source, account_id):
    prefix = f"{source}:uid:"
    if not account_id.startswith(prefix):
        raise RemediationError(f"account ID is not from this source: {account_id}")
    try:
        return int(account_id[len(prefix):])
    except ValueError as exc:
        raise RemediationError(f"malformed account ID: {account_id}") from exc


def _username_for(transport, uid):
    """Resolve uid -> username on the TARGET, never on the machine we run on."""
    rc, out, err = transport.run(["getent", "passwd", str(uid)])
    rows = out.strip().splitlines()
    fields = rows[0].split(':') if len(rows) == 1 else []
    if rc != 0 or len(fields) != 7 or fields[2] != str(uid) or not fields[0]:
        raise RemediationError(f"no account with uid {uid} on the target")
    return fields[0]


def _live_targets(transport, mapping, source, uid, entitlement):
    """Re-read the target and return the assignment and grant-path IDs that
    currently carry this account's hold on this entitlement.

    Scan v2 makes an approval name the exact assignment and grant paths it
    covers. Access can change between the scan a reviewer saw and the moment a
    revocation is executed, so the approved set is checked against a fresh
    reading rather than against the scan that produced it.
    """
    for account in discovery.discover(transport, mapping.managed_groups):
        if account.uid != uid:
            continue
        routes = normalize.held_entitlements(account, mapping, source).get(entitlement)
        if not routes:
            return set(), set()
        return ({normalize.assignment_id(source, uid, entitlement)},
                {route.path_id for route in routes})
    return set(), set()


def _describe(ids):
    return ", ".join(sorted(ids)) if ids else "none"


def _call(transport, args):
    rc, out, err = transport.run(["sudo", "-n", REMEDIATE, *args])
    try:
        result = json.loads(out)
        if not isinstance(result, dict) or type(result.get('ok')) is not bool or (rc != 0 and result['ok']):
            raise ValueError('Unsuccessful or malformed helper response')
        return result
    except ValueError as exc:
        raise RemediationError(
            f"remediation helper returned invalid JSON: {err.strip() or exc}") from exc


def revoke(request, mapping, transport, *, source, dry_run=False):
    """Execute one approved revocation. Returns the contract response dict.

    Success here is an acknowledgement only. Module 4 verifies by taking a
    separate scan and confirming the assignment is gone - this function never
    claims the access was removed.
    """
    request_id = request["request_id"]
    if not request.get('assignment_ids') or not request.get('grant_path_ids'):
        return {'request_id': request_id, 'status': 'failed', 'message': 'Nonempty approved target sets are required.'}

    if request.get("source") != source:
        return {"request_id": request_id, "status": "failed",
                "message": f"Request is for source {request.get('source')!r}, "
                           f"this connector serves {source!r}."}
    if request.get("mapping_version") != mapping.version:
        return {"request_id": request_id, "status": "failed",
                "message": f"Mapping version mismatch: request "
                           f"{request.get('mapping_version')!r}, connector "
                           f"{mapping.version!r}. Re-scan before approving."}

    entitlement = request["entitlement"]
    native = mapping.native_for(entitlement)
    if native is None:
        return {"request_id": request_id, "status": "failed",
                "message": f"Entitlement {entitlement} is outside this "
                           "connector's mapping scope."}

    try:
        uid = _uid_from_account_id(source, request["identity"])
        username = _username_for(transport, uid)
    except RemediationError as exc:
        return {"request_id": request_id, "status": "failed", "message": str(exc)}

    # The approved target set must still describe what is actually held. If the
    # access changed after approval - a group added, a path removed - the
    # approval no longer covers what is there, and the safe answer is to refuse
    # and make someone re-scan rather than remove something nobody approved.
    try:
        live_assignments, live_paths = _live_targets(
            transport, mapping, source, uid, entitlement)
    except (discovery.DiscoveryError, RemediationError) as exc:
        return {"request_id": request_id, "status": "failed",
                "message": f"Could not confirm the approved target set: {exc}"}

    approved_assignments = set(request.get("assignment_ids") or ())
    approved_paths = set(request.get("grant_path_ids") or ())
    if approved_assignments != live_assignments:
        return {"request_id": request_id, "status": "failed",
                "message": f"Approved assignment targets no longer match the "
                           f"source. Approved {_describe(approved_assignments)}; "
                           f"found {_describe(live_assignments)}. Re-scan before "
                           f"approving."}
    if approved_paths != live_paths:
        return {"request_id": request_id, "status": "failed",
                "message": f"Approved grant-path targets no longer match the "
                           f"source. Approved {_describe(approved_paths)}; "
                           f"found {_describe(live_paths)}. Re-scan before "
                           f"approving."}

    args = (["remove-sudo", username] if native["native_type"] == "sudo"
            else ["remove-group", username, native["native_id"]])
    if dry_run:
        args.append("--dry-run")

    try:
        result = _call(transport, args)
    except RemediationError as exc:
        return {"request_id": request_id, "status": "failed", "message": str(exc)}

    if not result.get("ok"):
        return {"request_id": request_id, "status": "failed",
                "message": f"Native removal refused: {result.get('error')}"
                           + (f" ({result['note']})" if result.get("note") else "")}

    if result.get("changed"):
        message = (f"Removed {native['native_type']} "
                   f"{native.get('native_id')} from {username}. "
                   "A separate verification scan is required.")
    else:
        message = (f"{username} already holds no {entitlement}. "
                   "A separate verification scan is required.")
    return {"request_id": request_id, "status": "succeeded", "message": message}
