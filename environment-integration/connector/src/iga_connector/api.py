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

from fastapi import Body, Depends, FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse

from . import discovery, normalize, remediation, transport as tp
from .normalize import Mapping

MAP_PATH = os.environ.get("IGA_MAPPING", "/opt/iga-lab/entitlement_map.json")
STATE_PATH = os.environ.get("IGA_STATE", "/var/lib/iga-connector/state.db")
TOKEN_HASH = os.environ.get("IGA_TOKEN_SHA256", "")
SOURCE = os.environ.get("IGA_SOURCE", "linux-lab")

app = FastAPI(title="IGA Linux connector", version="1.0.0")


# ----------------------------------------------------------------- mapping
def load_mapping():
    with open(MAP_PATH) as fh:
        return Mapping(json.load(fh))


# ------------------------------------------------------------------- state
def _db():
    os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
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
def scans(payload: dict = Body(...), _auth: bool = Depends(authorize)):
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
                                source=SOURCE, request_id=request_id, complete=True)


@app.post("/revocations")
def revocations(payload: dict = Body(...),
                idempotency_key: str = Header(default="", alias="Idempotency-Key"),
                _auth: bool = Depends(authorize)):
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
        link = tp.from_env()
        try:
            response = remediation.revoke(payload, mapping, link, source=SOURCE)
        finally:
            link.close()
        conn.execute("INSERT INTO receipts VALUES(?,?,?)",
                     (request_id, digest, json.dumps(response)))
    return response
