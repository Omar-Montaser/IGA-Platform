"""Approved removal, translated back into a native operation.

Every change goes through /usr/local/sbin/iga-remediate, which enforces the
guards (system accounts, the service account, primary groups, unmanaged groups,
sudoers validity). This module never runs gpasswd or edits sudoers itself, so
the guard set cannot be bypassed by a bug here.
"""
import json

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
    first = out.split(":", 1)[0].strip() if out else ""
    if rc != 0 or not first:
        raise RemediationError(f"no account with uid {uid} on the target")
    return first


def _call(transport, args):
    rc, out, err = transport.run(["sudo", "-n", REMEDIATE, *args])
    try:
        return json.loads(out)
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
