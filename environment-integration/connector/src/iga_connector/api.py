"""Module 3 HTTP service.

Exposes exactly the two endpoints Module 4's connector adapter calls:

    POST /scans        {source, request_id}                -> normalized scan
    POST /revocations  approved revocation request         -> {request_id, status, message}

Authentication is a bearer service credential compared in constant time.
Repeated request_ids are idempotent; the same ID with different content is
rejected, as the contract requires.
"""
import hashlib
import hmac
import json
import os
import sqlite3
from contextlib import closing
from datetime import datetime
import re

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

from . import discovery, normalize, remediation, transport as tp
from .normalize import Mapping

MAP_PATH = os.environ.get("IGA_MAPPING", "/opt/iga-lab/entitlement_map.json")
STATE_PATH = os.environ.get("IGA_STATE", "/var/lib/iga-connector/state.db")
TOKEN_HASH = os.environ.get("IGA_TOKEN_SHA256", "")
SOURCE = os.environ.get("IGA_SOURCE", "linux-lab")
# Scan v2 asks every account to declare a type. POSIX records none, so the
# service accounts are named here rather than guessed from the target. The
# account the connector authenticates as is always one of them.
SERVICE_ACCOUNTS = {
    name.strip() for name in
    os.environ.get("IGA_SERVICE_ACCOUNTS", "iga_svc").split(",") if name.strip()
} | {os.environ.get("IGA_SSH_USER", "").strip()} - {""}

app = FastAPI(title="IGA Linux connector", version="1.0.0")


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    source: str = Field(min_length=1, max_length=2000)
    request_id: str | None = Field(default=None, min_length=1, max_length=2000)


class RevocationRequest(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    request_id: str
    source: str
    identity: str
    entitlement: str
    approved_by: str
    approved_at: str
    reason: str
    scan_id: str
    mapping_version: str
    assignment_ids: list[str] = Field(min_length=1)
    grant_path_ids: list[str] = Field(min_length=1)

    @field_validator('*')
    @classmethod
    def valid_values(cls, value):
        values = value if isinstance(value, list) else [value]
        if any(not item or item != item.strip() or len(item) > 2000 or
               any(ord(char) < 32 or ord(char) == 127 for char in item) for item in values):
            raise ValueError('Expected nonempty bounded strings without control characters')
        if isinstance(value, list) and len(set(value)) != len(value):
            raise ValueError('Approved targets must be unique')
        return value

    @field_validator('approved_at')
    @classmethod
    def valid_timestamp(cls, value):
        if not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z', value):
            raise ValueError('Approval time must be a UTC timestamp')
        datetime.fromisoformat(value.replace('Z', '+00:00'))
        return value


# ----------------------------------------------------------------- mapping
def load_mapping():
    try:
        with open(MAP_PATH, encoding='utf-8') as fh:
            mapping = Mapping(json.load(fh))
        if mapping.source != SOURCE:
            raise ValueError('Mapping source mismatch')
        return mapping
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise HTTPException(503, 'Mapping is unreadable, invalid or belongs to another source.') from exc


# ------------------------------------------------------------------- state
def _db():
    os.makedirs(os.path.dirname(os.path.abspath(STATE_PATH)), exist_ok=True)
    conn = sqlite3.connect(STATE_PATH, timeout=10)
    conn.execute("CREATE TABLE IF NOT EXISTS receipts("
                 "request_id TEXT PRIMARY KEY, digest TEXT NOT NULL, "
                 "response TEXT NOT NULL)")
    return conn


def _digest(payload):
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


# -------------------------------------------------------------------- auth
def authorize(authorization: str = Header(default="")):
    if not TOKEN_HASH:
        raise HTTPException(503, "Connector has no service credential configured.")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(401, "A bearer service credential is required.")
    if not hmac.compare_digest(hashlib.sha256(token.encode()).hexdigest(), TOKEN_HASH):
        raise HTTPException(401, "Invalid service credential.")
    return True


# ------------------------------------------------------------------ errors
@app.exception_handler(HTTPException)
async def _error(_request, exc):
    codes = {400: "bad_request", 401: "unauthorized", 409: "conflict",
             422: "unprocessable", 503: "unavailable"}
    return JSONResponse(status_code=exc.status_code,
                        content={"error": {"code": codes.get(exc.status_code, "error"),
                                           "message": exc.detail}})


# --------------------------------------------------------------- endpoints
@app.get("/")
def root():
    return {"service": "iga-linux-connector", "version": "1.0.0", "source": SOURCE}


@app.get("/health")
def health():
    try:
        mapping = load_mapping()
    except Exception:
        return JSONResponse(status_code=503,
                            content={"status": "degraded", "mapping": "unreadable"})
    try:
        link = tp.from_env()
        target = link.describe()
        link.close()
    except tp.TransportError as exc:
        return JSONResponse(status_code=503,
                            content={"status": "degraded", "target": str(exc)})
    return {"status": "ok", "mapping_version": mapping.version,
            "scope": len(mapping.scope), "target": target}


@app.post("/scans")
def scans(payload: ScanRequest, _auth: bool = Depends(authorize)):
    payload = payload.model_dump()
    source = payload.get("source")
    request_id = payload.get("request_id")
    if source != SOURCE:
        raise HTTPException(400, f"This connector serves source {SOURCE!r}.")

    mapping = load_mapping()
    link = None
    try:
        link = tp.from_env()
        accounts = discovery.discover(link, mapping.managed_groups)
        mtimes = {}
    except (discovery.DiscoveryError, tp.TransportError) as exc:
        # A partial read is reported as incomplete rather than passed off as a
        # full picture: Module 4 suppresses inferences on incomplete scans.
        raise HTTPException(503, f"Discovery incomplete: {exc}")
    finally:
        if link is not None:
            link.close()

    return normalize.build_scan(accounts, mapping, mtimes=mtimes,
                                source=SOURCE, request_id=request_id, complete=True,
                                service_accounts=SERVICE_ACCOUNTS)


@app.post("/revocations")
def revocations(payload: RevocationRequest,
                idempotency_key: str = Header(default="", alias="Idempotency-Key"),
                _auth: bool = Depends(authorize)):
    payload = payload.model_dump()
    request_id = payload.get("request_id")
    if not request_id:
        raise HTTPException(400, "request_id is required.")
    if idempotency_key and idempotency_key != request_id:
        raise HTTPException(400, "Idempotency-Key must match request_id.")

    digest = _digest(payload)
    with closing(_db()) as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        prior = conn.execute(
            "SELECT digest, response FROM receipts WHERE request_id=?",
            (request_id,)).fetchone()
        if prior:
            if prior[0] != digest:
                raise HTTPException(409, "This request ID was already used with "
                                         "different content.")
            return json.loads(prior[1])

        mapping = load_mapping()
        link = None
        try:
            link = tp.from_env()
            response = remediation.revoke(payload, mapping, link, source=SOURCE)
        except (tp.TransportError, discovery.DiscoveryError) as exc:
            raise HTTPException(503, 'Source interaction failed; retry the same approved request.') from exc
        finally:
            if link is not None:
                link.close()
        conn.execute("INSERT INTO receipts VALUES(?,?,?)",
                     (request_id, digest, json.dumps(response)))
    return response
