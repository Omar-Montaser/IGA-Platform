// Execute the shipped JS with a minimal DOM stub; no browser/LLM claim.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '../static/app.js'), 'utf8');

function app(fetch = async () => { throw new Error('Unexpected request'); }) {
    const elements = new Map();
    const timers = new Map();
    let timerId = 0;
    const document = {
        addEventListener() {},
        querySelectorAll() { return []; },
        querySelector() { return null; },
        getElementById(id) {
            if (!elements.has(id)) elements.set(id, {
                textContent: 'old private data', hidden: false, value: '',
                classList: { add() {}, remove() {}, contains() { return false; } }, setAttribute() {},
                contains() { return false; }, querySelectorAll() { return []; }
            });
            return elements.get(id);
        }
    };
    const context = vm.createContext({ document, fetch, window: { location: { origin: 'http://localhost' } },
        crypto: require('node:crypto').webcrypto,
        setInterval(fn) { timers.set(++timerId, fn); return timerId; },
        clearInterval(id) { timers.delete(id); }, console: { error() {} } });
    vm.runInContext(source, context);
    return { run: expression => vm.runInContext(expression, context), document, timers };
}

test('HTML escaping is safe in quoted attributes as well as text', () => {
    const ui = app();
    const input = '"<img>&' + "'";
    assert.equal(ui.run(`escapeHtml(${JSON.stringify(input)})`), '&quot;&lt;img&gt;&amp;&#39;');
});

test('logout clears prior review data and admin controls', () => {
    const ui = app();
    ui.run(`state.token='old'; state.allFindings=[{secret:true}]; state.filteredFindings=[1]; logout();`);
    assert.equal(ui.run('state.token'), null);
    assert.equal(ui.run('state.allFindings.length + state.filteredFindings.length'), 0);
    assert.equal(ui.document.getElementById('audit-content').textContent, '');
    assert.equal(ui.document.getElementById('finding-content').textContent, '');
    assert.equal(ui.document.getElementById('audit-nav-btn').hidden, true);
});

test('responses started before logout cannot repopulate another session', async () => {
    let deliver;
    const ui = app(() => new Promise(resolve => { deliver = resolve; }));
    ui.run(`state.token='old';`);
    const pending = ui.run('api.getCampaigns()');
    ui.run(`logout(); state.token='new';`);
    deliver({ ok: true, headers: { get: () => 'application/json' }, json: async () => ({ secret: true }) });
    await assert.rejects(pending, /Session changed/);
    assert.equal(ui.run('state.token'), 'new');
});

const environment = (run = null) => ({ sources: [{ source: 'test', name: 'Test environment', mode: 'simulated',
    status: run?.state || 'never_scanned', inventory: null, can_start: !run, setup_error: null, run, latest_campaign: null }] });
const response = data => ({ ok: true, headers: { get: () => 'application/json' }, json: async () => data });

test('unchanged polling preserves the form DOM and typed campaign name', () => {
    const ui = app();
    const container = ui.document.getElementById('environment-content');
    let writes = 0;
    Object.defineProperty(container, 'innerHTML', { set() { writes++; } });
    ui.run(`renderEnvironment(${JSON.stringify(environment())}); campaignNames.set('test', 'Draft name');`);
    ui.run(`renderEnvironment(${JSON.stringify({ ...environment(), generated_at: 'later' })});`);
    assert.equal(writes, 1);
    assert.equal(ui.run(`campaignNames.get('test')`), 'Draft name');
});

test('network retry keeps exactly the same start key and body, suppressing concurrent clicks', async () => {
    const calls = [];
    let rejectStart;
    const ui = app((url, options) => {
        if (url.endsWith('/api/environments')) return Promise.resolve(response(environment()));
        calls.push(options);
        if (calls.length === 1) return new Promise((resolve, reject) => { rejectStart = reject; });
        return Promise.resolve(response({ id: 'run:one', state: 'queued' }));
    });
    ui.run(`state.user={role:'admin'}; campaignNames.set('test', 'Pinned name');`);
    const first = ui.run(`startEnvironmentReview('test')`);
    await ui.run(`startEnvironmentReview('test')`);
    assert.equal(calls.length, 1);
    rejectStart(new Error('Network lost'));
    await first;
    assert.equal(ui.run('pendingStarts.size'), 1);
    ui.run(`campaignNames.set('test', 'Changed draft');`);
    await ui.run(`startEnvironmentReview('test')`);
    assert.equal(calls[0].headers['Idempotency-Key'], calls[1].headers['Idempotency-Key']);
    assert.equal(calls[0].body, calls[1].body);
    assert.equal(ui.run('pendingStarts.size'), 0);
});

test('polling never overlaps requests and logout discards run data and stops timers', async () => {
    let deliver, count = 0;
    const ui = app(() => { count++; return new Promise(resolve => { deliver = resolve; }); });
    ui.run(`state.user={role:'admin'};`);
    const pending = ui.run('loadEnvironment()');
    await ui.run('loadEnvironment()');
    assert.equal(count, 1);
    ui.run(`logout(); state.user={role:'admin'};`);
    deliver(response(environment({ id: 'old-private-run', state: 'reviewing', attempts: 1 })));
    await pending;
    assert.equal(ui.run('state.environment'), null);
    assert.equal(ui.timers.size, 0);
});

test('admin sign-in recovers persisted run progress; reviewer sign-in only loads campaigns', async () => {
    const calls = [];
    const persisted = environment({ id: 'run:existing', name: 'Recovered', state: 'reviewing', attempts: 2, events: [] });
    const ui = app(async url => {
        calls.push(url);
        if (url.endsWith('/api/me')) return response({ role: 'admin', name: 'Admin' });
        return response(persisted);
    });
    await ui.run(`login('admin-token')`);
    assert.equal(ui.run('state.environment.sources[0].run.id'), 'run:existing');
    assert.equal(ui.timers.size, 1);
    ui.run('logout()');
    assert.equal(ui.timers.size, 0);
    const reviewer = app(async url => {
        assert.ok(!url.endsWith('/api/environments'));
        return response(url.endsWith('/api/me') ? { role: 'reviewer', name: 'Reviewer' } : { campaigns: [] });
    });
    await reviewer.run(`login('reviewer-token')`);
    assert.equal(reviewer.run('state.environment'), undefined);
});

test('run retries use the supported endpoint and blocked errors are escaped', async () => {
    const calls = [];
    const ui = app(async (url, options) => {
        calls.push([url, options.method]);
        return response(environment());
    });
    ui.run(`state.user={role:'admin'};`);
    await ui.run(`retryCampaignRun('run:failed', 'test')`);
    assert.ok(calls.some(([url, method]) => url.endsWith('/api/campaign-runs/run%3Afailed/retry') && method === 'POST'));
    ui.run(`renderEnvironment(${JSON.stringify(environment({ id: 'run:blocked', name: 'Blocked', state: 'blocked', attempts: 1, error: '<script>bad</script>', can_retry: false, events: [] }))});`);
    const html = ui.document.getElementById('environment-content').innerHTML;
    assert.match(html, /&lt;script&gt;bad&lt;\/script&gt;/);
    assert.ok(!html.includes('data-retry='));
});
