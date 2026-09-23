// Execute the shipped JS with a minimal DOM stub; no browser/LLM claim.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '../static/app.js'), 'utf8');

function app(fetch = async () => { throw new Error('Unexpected request'); }) {
    const elements = new Map();
    const document = {
        addEventListener() {},
        getElementById(id) {
            if (!elements.has(id)) elements.set(id, {
                textContent: 'old private data', hidden: false, value: '',
                classList: { add() {}, remove() {} }, setAttribute() {}
            });
            return elements.get(id);
        }
    };
    const context = vm.createContext({ document, fetch, window: { location: { origin: 'http://localhost' } },
                                      console: { error() {} } });
    vm.runInContext(source, context);
    return { run: expression => vm.runInContext(expression, context), document };
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
