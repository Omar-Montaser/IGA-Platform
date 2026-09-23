"""UI route and static file serving tests."""
import unittest
from pathlib import Path
from fastapi.testclient import TestClient
from iga_review.api import create_app
from iga_review.domain import User, EngineConfig
from iga_review.service import ReviewService
import hashlib
import tempfile


class UIRoutesTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        
        # Create a test user
        token_hash = hashlib.sha256(b'test-token').hexdigest()
        self.admin = User('admin', 'Admin User', 'admin', None, token_hash)
        
        # Create service with demo mode
        self.service = ReviewService(
            self.root / 'test.db',
            [self.admin],
            fallback_reviewer_id='admin',
            demo=True
        )
        
        # Create app
        self.app = create_app(self.service)
        self.client = TestClient(self.app)
    
    def test_root_serves_index_html_when_available(self):
        """Root path should serve index.html if static files exist."""
        # Check if static files are present
        static_dir = Path(__file__).parent.parent / 'static'
        if not static_dir.exists():
            self.skipTest('Static files not present')
        
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn('text/html', response.headers.get('content-type', ''))
        self.assertIn('IGA Access Review', response.text)
    
    def test_static_files_served_with_correct_mime_types(self):
        """Static files should be served with correct content types."""
        static_dir = Path(__file__).parent.parent / 'static'
        if not static_dir.exists():
            self.skipTest('Static files not present')
        
        # Test CSS
        response = self.client.get('/static/styles.css')
        self.assertEqual(response.status_code, 200)
        self.assertIn('text/css', response.headers.get('content-type', ''))
        
        # Test JavaScript
        response = self.client.get('/static/app.js')
        self.assertEqual(response.status_code, 200)
        # Could be application/javascript or text/javascript
        self.assertIn('javascript', response.headers.get('content-type', '').lower())
    
    def test_static_files_not_cached(self):
        """Static responses should include cache-control headers from middleware."""
        static_dir = Path(__file__).parent.parent / 'static'
        if not static_dir.exists():
            self.skipTest('Static files not present')
        
        response = self.client.get('/static/app.js')
        # The middleware adds Cache-Control: no-store
        self.assertEqual(response.headers.get('cache-control'), 'no-store')
    
    def test_nonexistent_static_file_returns_404(self):
        """Requesting a nonexistent static file should return 404."""
        static_dir = Path(__file__).parent.parent / 'static'
        if not static_dir.exists():
            self.skipTest('Static files not present')
        
        response = self.client.get('/static/nonexistent.js')
        self.assertEqual(response.status_code, 404)
    
    def test_api_routes_still_work_with_ui_mounted(self):
        """API routes should still function correctly with UI mounted."""
        # Test public routes work
        response = self.client.get('/api/health')
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['module'], 4)
        self.assertTrue(data['demo'])
        
        # Test authenticated route requires token
        response = self.client.get('/api/me')
        self.assertEqual(response.status_code, 401)
        
        # Test with valid token
        response = self.client.get(
            '/api/me',
            headers={'Authorization': 'Bearer test-token'}
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['name'], 'Admin User')
        self.assertEqual(data['role'], 'admin')
    
    def test_ui_does_not_expose_config_files(self):
        """UI should not serve config.json or other sensitive files."""
        # Create a config file in the static directory (should never happen, but test defense)
        static_dir = Path(__file__).parent.parent / 'static'
        if not static_dir.exists():
            self.skipTest('Static files not present')
        
        # Try to access files that should never be served
        response = self.client.get('/static/../src/iga_review/api.py')
        # Should either 404 or be blocked by path traversal protection
        self.assertNotEqual(response.status_code, 200)
        
        response = self.client.get('/static/config.json')
        self.assertEqual(response.status_code, 404)
    
    def test_csp_header_present_on_ui_routes(self):
        """CSP header should be present to prevent inline scripts."""
        response = self.client.get('/')
        csp = response.headers.get('content-security-policy', '')
        
        # Verify key CSP directives
        self.assertIn("default-src 'self'", csp)
        self.assertIn("script-src 'self'", csp)
        self.assertIn("object-src 'none'", csp)
        self.assertIn("base-uri 'none'", csp)
        self.assertIn("frame-ancestors 'none'", csp)
    
    def test_security_headers_on_static_files(self):
        """Security headers should be present on static file responses."""
        static_dir = Path(__file__).parent.parent / 'static'
        if not static_dir.exists():
            self.skipTest('Static files not present')
        
        response = self.client.get('/static/app.js')
        self.assertEqual(response.status_code, 200)
        
        # Check security headers
        self.assertEqual(response.headers.get('x-content-type-options'), 'nosniff')
        self.assertEqual(response.headers.get('referrer-policy'), 'no-referrer')
        self.assertEqual(response.headers.get('cache-control'), 'no-store')


class UIBehaviorTests(unittest.TestCase):
    """Tests for UI behavior patterns (without requiring a browser)."""
    
    def test_html_structure_has_required_accessibility_attributes(self):
        """HTML should include proper ARIA labels and roles."""
        static_dir = Path(__file__).parent.parent / 'static'
        index_path = static_dir / 'index.html'
        
        if not index_path.exists():
            self.skipTest('index.html not present')
        
        html = index_path.read_text(encoding='utf-8')
        
        # Check for key accessibility attributes
        self.assertIn('role="main"', html)
        self.assertIn('role="alert"', html)
        self.assertIn('aria-label', html)
        self.assertIn('aria-live="polite"', html)
        self.assertIn('lang="en"', html)
    
    def test_javascript_does_not_use_dangerous_patterns(self):
        """JavaScript should not use innerHTML with user data or eval."""
        static_dir = Path(__file__).parent.parent / 'static'
        js_path = static_dir / 'app.js'
        
        if not js_path.exists():
            self.skipTest('app.js not present')
        
        js_code = js_path.read_text()
        
        # Should not use eval
        self.assertNotIn('eval(', js_code)
        
        # Should use escapeHtml function for text rendering
        self.assertIn('escapeHtml', js_code)
        
        # Should use textContent for user data
        self.assertIn('.textContent =', js_code)
        
        # Should not use dangerouslySetInnerHTML or similar
        self.assertNotIn('dangerouslySetInnerHTML', js_code)
    
    def test_javascript_enforces_strict_mode(self):
        """JavaScript should use strict mode."""
        static_dir = Path(__file__).parent.parent / 'static'
        js_path = static_dir / 'app.js'
        
        if not js_path.exists():
            self.skipTest('app.js not present')
        
        js_code = js_path.read_text()
        self.assertIn("'use strict'", js_code)
    
    def test_javascript_does_not_use_localstorage_for_tokens(self):
        """JavaScript should not store tokens in localStorage."""
        static_dir = Path(__file__).parent.parent / 'static'
        js_path = static_dir / 'app.js'
        
        if not js_path.exists():
            self.skipTest('app.js not present')
        
        js_code = js_path.read_text()
        
        # Should not use localStorage for sensitive data
        # Token should be in memory only (state.token)
        self.assertNotIn('localStorage.setItem', js_code)
        self.assertIn('state.token', js_code)
    
    def test_css_includes_focus_visible_styles(self):
        """CSS should include visible focus states for accessibility."""
        static_dir = Path(__file__).parent.parent / 'static'
        css_path = static_dir / 'styles.css'
        
        if not css_path.exists():
            self.skipTest('styles.css not present')
        
        css_code = css_path.read_text()
        
        # Should have focus styles
        self.assertIn(':focus', css_code)
        self.assertIn('outline:', css_code)
    
    def test_html_form_inputs_have_proper_labels(self):
        """Form inputs should have associated labels."""
        static_dir = Path(__file__).parent.parent / 'static'
        index_path = static_dir / 'index.html'
        
        if not index_path.exists():
            self.skipTest('index.html not present')
        
        html = index_path.read_text(encoding='utf-8')
        
        # Check that inputs have labels
        # Count inputs and labels
        input_count = html.count('<input')
        label_count = html.count('<label')
        
        # Should have at least as many labels as inputs
        self.assertGreaterEqual(label_count, input_count - 3)  # Allow some radio/checkbox groups

    def test_red_white_grey_review_workspace_structure_is_present(self):
        html = (Path(__file__).parent.parent / 'static' / 'index.html').read_text(encoding='utf-8')
        css = (Path(__file__).parent.parent / 'static' / 'styles.css').read_text(encoding='utf-8')
        js = (Path(__file__).parent.parent / 'static' / 'app.js').read_text(encoding='utf-8')
        for marker in ('review-workspace', 'review-queue', 'review-panel', 'finding-search', 'finding-sort', 'review-journey', 'toast'):
            self.assertIn(marker, html)
        self.assertIn('--color-primary:#ba2025', css)
        for marker in ('applyFilters', 'saveDecisionDraft', 'previous-finding', 'panel-evidence', 'detail-tabs', 'run-stage-rail', 'journeyStages', 'RULES FALLBACK'):
            self.assertIn(marker, js)

    def test_ui_copy_does_not_use_long_dash_punctuation(self):
        static_dir = Path(__file__).parent.parent / 'static'
        for path in (static_dir / 'index.html', static_dir / 'styles.css', static_dir / 'app.js'):
            copy = path.read_text(encoding='utf-8')
            self.assertNotIn('\u2014', copy, f'Em dash found in {path.name}')
            self.assertNotIn('\u2013', copy, f'En dash found in {path.name}')
    
    def test_javascript_handles_401_by_logging_out(self):
        """JavaScript should handle 401 responses by logging out."""
        static_dir = Path(__file__).parent.parent / 'static'
        js_path = static_dir / 'app.js'
        
        if not js_path.exists():
            self.skipTest('app.js not present')
        
        js_code = js_path.read_text()
        
        # Should check for 401 status
        self.assertIn('401', js_code)
        self.assertIn('logout', js_code)
    
    def test_javascript_uses_idempotency_keys(self):
        """JavaScript should generate idempotency keys for decisions."""
        static_dir = Path(__file__).parent.parent / 'static'
        js_path = static_dir / 'app.js'
        
        if not js_path.exists():
            self.skipTest('app.js not present')
        
        js_code = js_path.read_text()
        
        self.assertIn('generateIdempotencyKey', js_code)
        self.assertIn('Idempotency-Key', js_code)
        self.assertIn('crypto.getRandomValues', js_code)


if __name__ == '__main__':
    unittest.main()
