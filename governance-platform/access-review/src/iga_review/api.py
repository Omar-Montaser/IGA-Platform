"""Same-origin authenticated API for the Module 4 review core."""
from pathlib import Path
import sqlite3
from urllib.parse import urlsplit
from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool
from pydantic import ValidationError
from iga_hr import BundleValidationError
from .domain import InputError, Scan, strict_json
from .service import ServiceError

MAX_BODY = 10 * 1024 * 1024


def create_app(service):
    app = FastAPI(title='IGA Access Review', version='2.0.0', docs_url=None, redoc_url=None, openapi_url=None)
    
    # Mount static files for the UI
    static_dir = Path(__file__).parent.parent.parent / 'static'
    if static_dir.exists():
        app.mount('/static', StaticFiles(directory=str(static_dir)), name='static')
    app.state.service = service

    def error(status, code, message):
        return JSONResponse({'error': {'code': code, 'message': message}}, status_code=status)

    @app.exception_handler(ServiceError)
    async def service_error(request, exc):
        return error(exc.status, exc.code, exc.message)

    @app.exception_handler(ValidationError)
    async def validation_error(request, exc):
        locations = ['.'.join(map(str, e['loc'])) for e in exc.errors(include_input=False)][:5]
        return error(422, 'invalid_input', 'Input validation failed at: ' + ', '.join(locations))

    @app.exception_handler(BundleValidationError)
    async def hr_error(request, exc):
        return error(422, 'invalid_hr_bundle', '; '.join(f'{i.path}: {i.message}' for i in exc.issues[:5]))

    @app.exception_handler(InputError)
    async def input_error(request, exc):
        return error(422, 'invalid_input', str(exc))

    @app.exception_handler(sqlite3.OperationalError)
    async def db_error(request, exc):
        return error(503, 'database_unavailable', 'Storage is temporarily unavailable; retry with the same request key.')

    @app.middleware('http')
    async def protection(request, call_next):
        origin = request.headers.get('origin')
        if origin:
            expected = f'{request.url.scheme}://{request.url.netloc}'
            if origin != expected:
                return error(403, 'origin_rejected', 'Cross-origin requests are not allowed.')
        if request.headers.get('sec-fetch-site') == 'cross-site':
            return error(403, 'origin_rejected', 'Cross-site requests are not allowed.')
        response = await call_next(request)
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['Cache-Control'] = 'no-store'
        return response

    def actor(request: Request):
        header = request.headers.get('authorization', '')
        if not header.startswith('Bearer ') or len(header) > 4096:
            raise ServiceError(401, 'unauthenticated', 'A reviewer credential is required.')
        return service.authenticate(header[7:])

    async def body(request):
        if request.headers.get('content-type', '').split(';')[0].strip() != 'application/json':
            raise ServiceError(415, 'content_type', 'Send application/json.')
        raw, size = [], 0
        async for chunk in request.stream():
            size += len(chunk)
            if size > MAX_BODY:
                raise ServiceError(413, 'body_too_large', 'The request exceeds 10 MiB.')
            raw.append(chunk)
        data = b''.join(raw)
        try:
            decoded = data.decode('utf-8')
        except UnicodeDecodeError as exc:
            raise InputError('Request must be UTF-8 JSON') from exc
        return strict_json(decoded), decoded

    @app.get('/api/health')
    def health():
        return {'status': 'ok', 'module': 4, 'demo': service.demo}

    @app.get('/api/me')
    def me(user=Depends(actor)):
        return {**user.public(), 'demo': service.demo, 'ai_provider': service.explainer.provider,
                'ai_model': getattr(service.explainer, 'model', None)}

    @app.get('/api/campaigns')
    def campaigns(user=Depends(actor)):
        return service.list_campaigns(user)

    @app.post('/api/campaigns', status_code=201)
    async def import_campaign(request: Request, user=Depends(actor)):
        service._admin(user)
        payload, raw = await body(request)
        return await run_in_threadpool(service.create_campaign, payload, user, raw_json=raw)

    @app.get('/api/campaigns/{campaign_id}')
    def campaign(campaign_id: str, user=Depends(actor)):
        return service.get_campaign(campaign_id, user)

    @app.get('/api/findings/{finding_id}')
    def finding(finding_id: str, user=Depends(actor)):
        return service.get_finding(finding_id, user)

    @app.post('/api/findings/{finding_id}/decisions')
    async def decide(finding_id: str, request: Request, user=Depends(actor)):
        payload, _ = await body(request)
        return service.decide(finding_id, user, payload, request.headers.get('idempotency-key'))

    @app.post('/api/findings/{finding_id}/explanation')
    def explanation(finding_id: str, user=Depends(actor)):
        return service.explain(finding_id, user)

    @app.post('/api/campaigns/{campaign_id}/process')
    def process(campaign_id: str, user=Depends(actor)):
        return service.process(campaign_id, user)

    @app.post('/api/remediations/{request_id}/retry')
    def retry(request_id: str, user=Depends(actor)):
        return service.retry(request_id, user)

    @app.get('/api/campaigns/{campaign_id}/audit')
    def audit(campaign_id: str, user=Depends(actor)):
        return service.audit(campaign_id, user)

    @app.get('/api/campaigns/{campaign_id}/export')
    def export(campaign_id: str, user=Depends(actor)):
        return service.export(campaign_id, user)

    @app.get('/api/schemas/scan')
    def schema(user=Depends(actor)):
        return Scan.model_json_schema()

    @app.get('/')
    def index():
        # Serve the UI if available
        ui_path = Path(__file__).parent.parent.parent / 'static' / 'index.html'
        if ui_path.exists():
            return FileResponse(ui_path)
        # Fallback to API status
        return {
            'name': 'IGA Access Review API',
            'module': 4,
            'version': '2.0.0',
            'health': '/api/health',
            'status': 'core API ready; reviewer UI is available at /',
        }

    return app
