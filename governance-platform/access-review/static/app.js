// IGA Access Review UI - Vanilla JavaScript SPA
// Security: Bearer token kept in memory only, server-side authorization enforced

'use strict';

// State management
const state = {
    sessionVersion: 0,
    token: null,
    user: null,
    campaigns: [],
    currentCampaign: null,
    currentFinding: null,
    allFindings: [],
    filteredFindings: [],
    findingRequest: 0
};

const decisionDrafts = new Map();
const decisionRequests = new Map();
let toastTimer = null;

function notify(message) {
    const toast = document.getElementById('toast');
    toast.textContent = message;
    toast.classList.remove('hidden');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.add('hidden'), 4500);
}

function initials(name) {
    return String(name || '?').split(/[ ._-]+/).filter(Boolean).slice(0, 2).map(word => word[0]).join('').toUpperCase();
}

function friendly(value) { return String(value || 'Unknown').replace(/_/g, ' '); }

// API client
const api = {
    baseUrl: window.location.origin,
    
    async request(endpoint, options = {}) {
        const sessionVersion = state.sessionVersion;
        const assertSession = () => {
            if (sessionVersion !== state.sessionVersion) throw new Error('Session changed; response discarded.');
        };
        const headers = {
            'Content-Type': 'application/json',
            ...options.headers
        };
        
        if (state.token) {
            headers['Authorization'] = `Bearer ${state.token}`;
        }
        
        const config = {
            ...options,
            headers
        };
        
        try {
            const response = await fetch(`${this.baseUrl}${endpoint}`, config);
            assertSession();
            
            // Handle error responses
            if (!response.ok) {
                if (response.status === 401) {
                    // Token invalid/expired - logout
                    logout('Session expired. Please sign in again.');
                    throw new Error('Authentication required');
                }
                
                let errorData;
                try {
                    errorData = await response.json();
                    assertSession();
                } catch {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }
                
                const message = errorData.error?.message || `Request failed: ${response.status}`;
                const error = new Error(message);
                error.status = response.status;
                error.code = errorData.error?.code;
                throw error;
            }
            
            // Success - return JSON
            const contentType = response.headers.get('content-type');
            if (contentType && contentType.includes('application/json')) {
                const data = await response.json();
                assertSession();
                return data;
            }
            return null;
        } catch (error) {
            if (error.message === 'Authentication required') {
                throw error;
            }
            console.error('API request failed:', error);
            throw error;
        }
    },
    
    async getMe() {
        return this.request('/api/me');
    },
    
    async getCampaigns() {
        return this.request('/api/campaigns');
    },
    
    async getCampaign(id) {
        return this.request(`/api/campaigns/${encodeURIComponent(id)}`);
    },
    
    async getFinding(id) {
        return this.request(`/api/findings/${encodeURIComponent(id)}`);
    },
    
    async makeDecision(findingId, decision, idempotencyKey) {
        return this.request(`/api/findings/${encodeURIComponent(findingId)}/decisions`, {
            method: 'POST',
            headers: {
                'Idempotency-Key': idempotencyKey
            },
            body: JSON.stringify(decision)
        });
    },
    
    async processCampaign(campaignId) {
        return this.request(`/api/campaigns/${encodeURIComponent(campaignId)}/process`, {
            method: 'POST'
        });
    },
    
    async retryRemediation(requestId) {
        return this.request(`/api/remediations/${encodeURIComponent(requestId)}/retry`, {
            method: 'POST'
        });
    },
    
    async getAudit(campaignId) {
        return this.request(`/api/campaigns/${encodeURIComponent(campaignId)}/audit`);
    },
    
    async exportCampaign(campaignId) {
        return this.request(`/api/campaigns/${encodeURIComponent(campaignId)}/export`);
    }
};

// Utility functions
function escapeHtml(text) {
    const entities = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
    return String(text ?? '').replace(/[&<>"']/g, character => entities[character]);
}

function formatDate(isoString) {
    if (!isoString) return 'N/A';
    try {
        const date = new Date(isoString);
        return date.toLocaleString();
    } catch {
        return isoString;
    }
}

function generateIdempotencyKey() {
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}

function showLoading(show = true) {
    const overlay = document.getElementById('loading-overlay');
    if (show) {
        overlay.classList.remove('hidden');
        overlay.setAttribute('aria-busy', 'true');
    } else {
        overlay.classList.add('hidden');
        overlay.setAttribute('aria-busy', 'false');
    }
}

function showError(elementId, message) {
    const element = document.getElementById(elementId);
    if (element) {
        element.textContent = message;
        // Announce to screen readers
        element.setAttribute('role', 'alert');
    }
}

function clearError(elementId) {
    const element = document.getElementById(elementId);
    if (element) {
        element.textContent = '';
    }
}

// Authentication
async function login(token) {
    const sessionVersion = ++state.sessionVersion;
    try {
        showLoading();
        clearError('login-error');
        
        state.token = token.trim();
        
        // Verify token by fetching user info
        const user = await api.getMe();
        state.user = user;
        
        // Show main view
        document.getElementById('login-view').classList.add('hidden');
        document.getElementById('main-view').classList.remove('hidden');
        
        // Update header
        document.getElementById('user-name').textContent = user.name;
        document.getElementById('token-input').value = '';
        const roleBadge = document.getElementById('user-role');
        roleBadge.textContent = user.role;
        roleBadge.className = `badge ${user.role}`;
        
        // Show audit nav for admins
        const isAdmin = user.role === 'admin';
        document.getElementById('audit-nav-btn').hidden = !isAdmin;
        document.getElementById('environment-nav-btn').hidden = !isAdmin;
        
        // Administrators begin with configured environments, even with no campaigns.
        if (isAdmin) await loadEnvironment();
        else await loadCampaigns();
        
        showLoading(false);
    } catch (error) {
        if (sessionVersion !== state.sessionVersion) return;
        showLoading(false);
        state.token = null;
        state.user = null;
        showError('login-error', error.message || 'Authentication failed. Please check your credential.');
    }
}

function logout(message = null) {
    state.sessionVersion += 1;
    state.findingRequest += 1;
    decisionDrafts.clear();
    decisionRequests.clear();
    document.getElementById('toast').classList.add('hidden');
    stopEnvironmentPolling();
    state.token = null;
    state.user = null;
    state.campaigns = [];
    state.currentCampaign = null;
    state.currentFinding = null;
    state.allFindings = [];
    state.filteredFindings = [];
    state.environment = null;
    environmentRenderKey = null;
    environmentRequest = null;
    pendingStarts.clear();
    campaignNames.clear();
    environmentActions.clear();
    for (const id of ['campaigns-list', 'campaign-actions', 'campaign-summary', 'campaign-warnings',
                      'findings-list', 'finding-content', 'audit-content', 'audit-campaign-select',
                      'user-name', 'user-role', 'campaign-name', 'portfolio-summary', 'campaign-context', 'queue-count', 'environment-content', 'environment-error', 'env-freshness']) {
        document.getElementById(id).textContent = '';
    }
    document.getElementById('audit-nav-btn').hidden = true;
    document.getElementById('environment-nav-btn').hidden = true;
    
    document.getElementById('main-view').classList.add('hidden');
    document.getElementById('login-view').classList.remove('hidden');
    document.getElementById('token-input').value = '';
    
    if (message) {
        showError('login-error', message);
    }
}

// Navigation
function showView(viewId) {
    const location = { 'campaigns-view': 'Access reviews', 'campaign-detail-view': 'Review workspace', 'environment-view': 'Environment', 'audit-view': 'Audit trail' };
    document.getElementById('page-location').textContent = location[viewId] || 'Access reviews';
    if (viewId !== 'environment-view') stopEnvironmentPolling();
    // Hide all content views
    document.querySelectorAll('.content-view').forEach(view => {
        view.classList.add('hidden');
    });
    
    // Show selected view
    const targetView = document.getElementById(viewId);
    if (targetView) {
        targetView.classList.remove('hidden');
    }
    
    // Update nav buttons
    document.querySelectorAll('.nav-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    const activeBtn = document.querySelector(`.nav-btn[data-view="${viewId}"]`)
        || document.querySelector(`.nav-btn[data-view="${(viewId === 'campaign-detail-view' ? 'campaigns' : viewId.replace(/-view$/, ''))}"]`);
    if (activeBtn) {
        activeBtn.classList.add('active');
    }
}

// Campaign list
async function loadCampaigns() {
    try {
        showLoading();
        clearError('campaigns-error');
        
        const data = await api.getCampaigns();
        state.campaigns = data.campaigns;
        
        renderCampaigns();
        showView('campaigns-view');
        showLoading(false);
    } catch (error) {
        showLoading(false);
        showError('campaigns-error', error.message || 'Failed to load campaigns');
    }
}

function renderCampaigns() {
    const container = document.getElementById('campaigns-list');
    const totals = state.campaigns.reduce((result, c) => ({ total: result.total + c.summary.total, pending: result.pending + c.summary.pending, critical: result.critical + c.summary.critical }), { total: 0, pending: 0, critical: 0 });
    document.getElementById('portfolio-summary').innerHTML = [
        ['Active campaigns', state.campaigns.filter(c => !c.superseded_by).length, 'Current reviews'],
        ['Awaiting review', totals.pending, 'Across visible campaigns'],
        ['Critical findings', totals.critical, 'Prioritize these reviews'],
        ['Total findings', totals.total, 'Including campaign history']
    ].map(([label, value, note]) => `<div class="summary-card"><div class="label">${label}</div><div class="value">${value}</div><small>${note}</small></div>`).join('');
    container.innerHTML = state.campaigns.length ? state.campaigns.map(campaign => {
        const completed = campaign.summary.total - campaign.summary.pending;
        const review = campaign.metadata?.review;
        return `<button type="button" class="campaign-card campaign-tile" data-campaign-id="${escapeHtml(campaign.id)}">
            <div class="tile-top"><span class="tile-icon" aria-hidden="true">[ ]</span><span class="badge ${campaign.superseded_by ? 'neutral' : 'pending'}">${campaign.superseded_by ? 'Superseded' : campaign.summary.pending ? 'In review' : 'Decisions recorded'}</span></div>
            <h3>${escapeHtml(campaign.name)}</h3><p class="help-text">${escapeHtml(campaign.source)} · ${escapeHtml(formatDate(campaign.created_at))}</p>
            <div class="campaign-counts"><span><strong>${campaign.summary.total}</strong> findings</span><span><strong>${campaign.summary.pending}</strong> pending</span><span class="risk-text"><strong>${campaign.summary.critical + campaign.summary.high}</strong> high / critical</span></div>
            <div class="progress-label"><span>Decisions recorded</span><strong>${completed} / ${campaign.summary.total}</strong></div>
            <progress value="${completed}" max="${campaign.summary.total || 1}" aria-label="Decisions recorded"></progress>
            <div class="tile-footer"><span>${review ? `${review.fallback_cases} rules fallbacks` : 'Evidence available'}${campaign.warnings.length ? ` · ${campaign.warnings.length} warnings` : ''}</span><strong>Open review <span aria-hidden="true">-&gt;</span></strong></div>
        </button>`;
    }).join('') : '<div class="empty-state"><span class="empty-symbol" aria-hidden="true">[ ]</span><h3>Your next review starts here</h3><p>No campaigns are available. Administrators can start an access review from Environment.</p></div>';
    container.querySelectorAll('[data-campaign-id]').forEach(card => card.addEventListener('click', () => loadCampaign(card.dataset.campaignId)));
}

// Campaign detail
async function loadCampaign(campaignId) {
    try {
        showLoading();
        clearError('campaign-detail-error');
        
        const campaign = await api.getCampaign(campaignId);
        state.currentCampaign = campaign;
        state.currentFinding = null;
        state.findingRequest += 1;
        for (const id of ['finding-search', 'risk-filter', 'status-filter']) document.getElementById(id).value = '';
        document.getElementById('finding-content').innerHTML = '<div class="empty-state"><span class="empty-symbol" aria-hidden="true">( )</span><h3>Select an access finding</h3><p>Explore its evidence, assess the risk, and make an informed decision.</p></div>';
        state.allFindings = campaign.findings;
        state.filteredFindings = campaign.findings;
        
        renderCampaignDetail();
        showView('campaign-detail-view');
        showLoading(false);
    } catch (error) {
        showLoading(false);
        showError('campaign-detail-error', error.message || 'Failed to load campaign');
    }
}

function renderCampaignDetail() {
    const campaign = state.currentCampaign;
    
    // Header
    document.getElementById('campaign-name').textContent = campaign.name;
    const review = campaign.metadata?.review;
    document.getElementById('campaign-context').textContent = `${campaign.source} · ${review ? `${review.cases - review.fallback_cases} AI-reviewed cases · ${review.fallback_cases} rules fallbacks` : 'Evidence-backed review'}`;
    
    // Warnings
    const warningsEl = document.getElementById('campaign-warnings');
    if (campaign.warnings.length > 0) {
        warningsEl.hidden = false;
        warningsEl.innerHTML = `
            <strong>⚠ Campaign Warnings:</strong>
            <ul>
                ${campaign.warnings.map(w => `<li>${escapeHtml(w)}</li>`).join('')}
            </ul>
        `;
    } else {
        warningsEl.hidden = true;
    }
    
    // Actions (admin only)
    const actionsEl = document.getElementById('campaign-actions');
    if (state.user.role === 'admin') {
        actionsEl.innerHTML = `
            <button type="button" id="process-campaign-btn">Process Remediation</button>
            <button type="button" id="export-campaign-btn" class="secondary">Export</button>
        `;
        
        document.getElementById('process-campaign-btn').addEventListener('click', async () => {
            try {
                showLoading();
                await api.processCampaign(campaign.id);
                showLoading(false);
                notify('Remediation processed. Updated verification status is available.');
                await loadCampaign(campaign.id);
            } catch (error) {
                showLoading(false);
                alert('Failed to process remediation: ' + error.message);
            }
        });
        
        document.getElementById('export-campaign-btn').addEventListener('click', async () => {
            try {
                showLoading();
                const data = await api.exportCampaign(campaign.id);
                const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `campaign-${campaign.id}-export.json`;
                a.click();
                URL.revokeObjectURL(url);
                showLoading(false);
            } catch (error) {
                showLoading(false);
                alert('Failed to export campaign: ' + error.message);
            }
        });
    } else {
        actionsEl.innerHTML = '';
    }
    
    // Summary
    document.getElementById('campaign-summary').innerHTML = `
        <div class="summary-card">
            <div class="value">${campaign.summary.total}</div>
            <div class="label">Total Findings</div>
        </div>
        <div class="summary-card">
            <div class="value">${campaign.summary.pending}</div>
            <div class="label">Pending</div>
        </div>
        <div class="summary-card">
            <div class="value">${campaign.summary.critical}</div>
            <div class="label">Critical</div>
        </div>
        <div class="summary-card">
            <div class="value">${campaign.summary.high}</div>
            <div class="label">High</div>
        </div>
        <div class="summary-card">
            <div class="value">${campaign.summary.verified}</div>
            <div class="label">Verified</div>
        </div>
    `;
    const total = campaign.summary.total || 0;
    const pending = campaign.summary.pending || 0;
    const verified = campaign.summary.verified || 0;
    const completed = Math.max(0, total - pending);
    const journey = pending ? 1 : verified ? 3 : 2;
    const journeyStages = [
        ['evidence', 'Evidence captured', 'Fresh source snapshot'],
        ['review', 'Findings ready', `${total} access findings`],
        ['decisions', 'Human decisions', pending ? `${pending} still pending` : `${completed} decisions recorded`],
        ['verify', 'Verified outcome', verified ? `${verified} removals verified` : 'Follows approved changes']
    ];
    document.getElementById('review-journey').innerHTML = `<div class="journey-heading"><div><p class="eyebrow">REVIEW JOURNEY</p><h3>${pending ? 'Work through the queue' : verified ? 'Review complete with verified outcomes' : 'Ready for human decisions'}</h3></div><span class="journey-progress">${completed} / ${total} decisions</span></div><div class="journey-rail">${journeyStages.map(([key, label, detail], index) => { const state = index < journey ? 'complete' : index === journey ? 'current' : 'pending'; return `<div class="journey-stage ${state}"><span class="journey-marker">${state === 'complete' ? '✓' : index + 1}</span><div><strong>${label}</strong><small>${detail}</small></div></div>${index < journeyStages.length - 1 ? '<span class="journey-connector" aria-hidden="true"></span>' : ''}`; }).join('')}</div>`;
    
    // Findings
    applyFilters();
}

function applyFilters() {
    const risk = document.getElementById('risk-filter').value;
    const status = document.getElementById('status-filter').value;
    const query = document.getElementById('finding-search').value.trim().toLowerCase();
    const sort = document.getElementById('finding-sort').value;
    state.filteredFindings = state.allFindings.filter(f => (!risk || f.risk_level === risk) && (!status || f.status === status)
        && (!query || [f.identity_name, f.username, f.entitlement_name, f.department, f.role].some(value => String(value || '').toLowerCase().includes(query))))
        .sort((a, b) => sort === 'name' ? a.identity_name.localeCompare(b.identity_name) : sort === 'pending'
            ? Number(b.status === 'pending') - Number(a.status === 'pending') || b.risk_score - a.risk_score : b.risk_score - a.risk_score);
    renderFindings();
}

function renderFindings() {
    document.getElementById('queue-count').textContent = `${state.filteredFindings.length} / ${state.allFindings.length}`;
    const container = document.getElementById('findings-list');
    container.innerHTML = state.filteredFindings.length ? state.filteredFindings.map(f => `
        <button type="button" class="finding-card ${state.currentFinding?.id === f.id ? 'selected' : ''}" data-finding-id="${escapeHtml(f.id)}" aria-pressed="${state.currentFinding?.id === f.id}" aria-label="Review ${escapeHtml(f.identity_name)}: ${escapeHtml(f.entitlement_name)}">
            <div class="finding-row"><span class="avatar">${escapeHtml(initials(f.identity_name))}</span><span class="finding-identity"><strong>${escapeHtml(f.identity_name)}</strong><small>${escapeHtml(f.department)} · ${escapeHtml(f.username)}</small></span><span class="badge ${escapeHtml(f.risk_level)}">${escapeHtml(f.risk_level)}</span></div>
            <h3>${escapeHtml(f.entitlement_name)}</h3>
            <div class="finding-row finding-footer"><span class="badge ${escapeHtml(f.status)}">${escapeHtml(friendly(f.status))}</span><span>${f.decision_blockers?.length ? 'Decision blocked' : escapeHtml(friendly(f.recommended_action || f.recommendation))}<span aria-hidden="true"> -&gt;</span></span></div>
        </button>`).join('') : '<div class="empty-state compact"><h3>No matching findings</h3><p>Try another search or clear your filters.</p></div>';
    container.querySelectorAll('[data-finding-id]').forEach(card => card.addEventListener('click', () => loadFinding(card.dataset.findingId)));
}

function saveDecisionDraft() {
    const form = document.getElementById('decision-form');
    if (form && state.currentFinding) {
        const data = new FormData(form);
        decisionDrafts.set(state.currentFinding.id, { action: data.get('action'), reason: data.get('reason'), acknowledge: data.get('acknowledge_risk') === 'true' });
    }
}

async function loadFinding(findingId) {
    saveDecisionDraft();
    const request = ++state.findingRequest;
    const session = state.sessionVersion;
    const campaignId = state.currentCampaign?.id;
    try {
        clearError('finding-error');
        document.getElementById('review-panel').setAttribute('aria-busy', 'true');
        const finding = await api.getFinding(findingId);
        if (request !== state.findingRequest || session !== state.sessionVersion || campaignId !== state.currentCampaign?.id) return;
        state.currentFinding = finding;
        renderFindingDetail();
        renderFindings();
    } catch (error) {
        if (request === state.findingRequest && session === state.sessionVersion) showError('finding-error', error.message || 'Unable to load finding');
    } finally {
        if (request === state.findingRequest) document.getElementById('review-panel').setAttribute('aria-busy', 'false');
    }
}

function renderFindingDetail() {
    const f = state.currentFinding;
    const assessment = f.explanation;
    const currentIndex = state.filteredFindings.findIndex(item => item.id === f.id);
    const field = (label, value) => `<div class="detail-item"><span class="detail-label">${label}</span><span class="detail-value">${escapeHtml(value ?? 'Not recorded')}</span></div>`;
    const list = values => `<ul class="evidence-list">${values.map(value => `<li>${escapeHtml(value)}</li>`).join('')}</ul>`;
    const decision = f.can_decide ? renderDecisionForm(f) : `<div class="decision-form"><p class="eyebrow">DECISION</p><h3>${f.decision_blockers?.length ? 'Review is blocked' : 'Decision recorded'}</h3>${f.decision_blockers?.length ? list(f.decision_blockers) : `<p>This finding is ${escapeHtml(friendly(f.status))}.</p>`}</div>`;
    document.getElementById('finding-content').innerHTML = `
        <div class="finding-profile"><span class="avatar large">${escapeHtml(initials(f.identity_name))}</span><div><p class="eyebrow">ACCESS FINDING</p><h2>${escapeHtml(f.identity_name)}</h2><p>${escapeHtml(f.role)} · ${escapeHtml(f.department)}</p></div><span class="badge ${escapeHtml(f.risk_level)}">${escapeHtml(f.risk_level)} risk</span></div>
        <div class="access-heading"><span class="tile-icon" aria-hidden="true">-&gt;</span><div><h3>${escapeHtml(f.entitlement_name)}</h3><p>${escapeHtml(f.source)} · ${escapeHtml(f.username)}</p></div></div>
        <div class="review-navigation"><span>${currentIndex < 0 ? 'Outside current filters' : `Finding ${currentIndex + 1} of ${state.filteredFindings.length}`}</span><div><button type="button" class="secondary" id="previous-finding" ${currentIndex <= 0 ? 'disabled' : ''} aria-label="Previous finding">&lt;-</button><button type="button" class="secondary" id="next-finding" ${currentIndex < 0 || currentIndex >= state.filteredFindings.length - 1 ? 'disabled' : ''} aria-label="Next finding">-&gt;</button></div></div>
        <div class="detail-tabs" role="tablist" aria-label="Finding information"><button type="button" role="tab" id="tab-assessment" aria-selected="true" aria-controls="panel-assessment" data-detail-tab="assessment">Assessment</button><button type="button" role="tab" id="tab-evidence" aria-selected="false" aria-controls="panel-evidence" data-detail-tab="evidence" tabindex="-1">Access evidence</button><button type="button" role="tab" id="tab-context" aria-selected="false" aria-controls="panel-context" data-detail-tab="context" tabindex="-1">Identity context</button></div>
        <section id="panel-assessment" class="detail-tab-panel" role="tabpanel" aria-labelledby="tab-assessment">
            <div class="assessment-callout"><p class="eyebrow">${assessment?.status === 'ready' ? 'AI ASSESSMENT' : 'RULES FALLBACK · NOT AI'}</p><h3>${escapeHtml(friendly(f.recommended_action || f.recommendation))}</h3><p>${escapeHtml(f.item_assessment?.reasoning || assessment?.reasoning || 'No assessment is available.')}</p></div>
            <div class="finding-detail-section"><h3>Policy & risk</h3><p>${escapeHtml(f.policy_fact?.text || friendly(f.policy_result))}</p><div class="risk-score"><strong>${f.risk_score}<small>/100</small></strong><span>Risk triage score<br><small>A heuristic, not an authorization decision</small></span></div>${(f.signals || []).map(signal => `<div class="signal-item"><span><strong>${escapeHtml(friendly(signal.code))}</strong><small>${escapeHtml(signal.message)}</small></span><span class="signal-points">+${signal.points}</span></div>`).join('')}</div>
            ${f.mandatory_human_review ? `<div class="notice"><strong>Human review required</strong><p>${(f.human_review_reasons || []).map(reason => escapeHtml(friendly(reason))).join(' · ')}</p></div>` : ''}
            ${assessment ? `<details class="assessment-details"><summary>Full case assessment & provider</summary><p>${escapeHtml(assessment.reasoning || '')}</p><p>Provider: <strong>${escapeHtml(assessment.provider)}</strong>${assessment.model ? ` · Model: ${escapeHtml(assessment.model)}` : ''}${assessment.fallback_reason ? ` · Fallback: ${escapeHtml(friendly(assessment.fallback_reason))}` : ''}${assessment.attempted_provider ? ` · Attempted: ${escapeHtml(assessment.attempted_provider)}` : ''}</p><p>${assessment.status === 'ready' ? `Model self-reported confidence: ${Math.round(assessment.confidence * 100)}% (not a measured probability)` : 'Confidence is not applicable to rules fallback.'}</p>${list(assessment.open_questions || [])}${list(assessment.missing_evidence || [])}<p class="help-text">${(f.item_assessment?.evidence_refs || []).map(escapeHtml).join(', ')}</p></details>` : ''}
        </section>
        <section id="panel-evidence" class="detail-tab-panel" role="tabpanel" aria-labelledby="tab-evidence" hidden>
            <div class="finding-detail-section"><h3>Observed access paths</h3><p class="help-text">How this account holds the reviewed capability.</p>${(f.review_evidence?.grant_paths || []).map(path => `<div class="grant-path"><span class="badge">${escapeHtml(path.grant_type)}</span><div>${path.path.map(node => `<span>${escapeHtml(node.ref)}</span>`).join('<b aria-hidden="true">-&gt;</b>')}</div></div>`).join('') || '<p>No grant paths are recorded for this finding.</p>'}</div>
            ${(f.evidence_gaps || []).length ? `<div class="notice"><strong>Evidence limits</strong>${list(f.evidence_gaps)}</div>` : ''}
            <div class="detail-grid">${field('Observation', f.evidence?.scanned_at ? formatDate(f.evidence.scanned_at) : null)}${field('Scan ID', f.evidence?.scan_id)}${field('Mapping version', f.evidence?.mapping_version)}${field('HR snapshot', f.evidence?.snapshot_at ? formatDate(f.evidence.snapshot_at) : null)}</div>
            <details class="assessment-details"><summary>Full source evidence</summary><pre>${escapeHtml(JSON.stringify(f.review_evidence || {}, null, 2))}</pre></details>
        </section>
        <section id="panel-context" class="detail-tab-panel" role="tabpanel" aria-labelledby="tab-context" hidden><div class="detail-grid">${field('Identity', f.identity_name)}${field('Account', f.username)}${field('Department', f.department)}${field('Role', f.role)}${field('Employment', friendly(f.employment_status))}${field('Privileged access', f.privileged === null ? 'Unknown' : f.privileged ? 'Yes' : 'No')}${field('Sensitivity', f.sensitivity)}${field('Assigned reviewer', f.reviewer_id)}${field('Routing', f.routing_reason)}</div>${f.peer?.available ? `<div class="finding-detail-section"><h3>Peer context</h3><p>${f.peer.holders} of ${f.peer.count} comparable peers hold this capability.</p><p class="help-text">${escapeHtml(f.peer.reason)}</p></div>` : ''}</section>
        ${decision}
        ${f.remediation ? `<div class="finding-detail-section remediation-card"><h3>Remediation</h3><span class="badge ${escapeHtml(f.remediation.state)}">${escapeHtml(friendly(f.remediation.state))}</span><p class="help-text">${escapeHtml(f.remediation.id)}</p>${f.remediation.last_error ? `<p class="error">${escapeHtml(f.remediation.last_error)}</p>` : ''}${state.user.role === 'admin' && ['failed', 'verification_failed'].includes(f.remediation.state) ? '<button type="button" id="retry-remediation-btn">Retry remediation</button>' : ''}</div>` : ''}`;
    attachFindingHandlers(f);
    const draft = decisionDrafts.get(f.id);
    if (draft && f.can_decide) {
        document.getElementById('decision-reason').value = draft.reason || '';
        const radio = document.getElementById('action-' + draft.action);
        if (radio) radio.checked = true;
        const ack = document.getElementById('acknowledge-risk');
        if (ack) ack.checked = draft.acknowledge;
    }
    document.getElementById('previous-finding').addEventListener('click', () => loadFinding(state.filteredFindings[currentIndex - 1].id));
    document.getElementById('next-finding').addEventListener('click', () => loadFinding(state.filteredFindings[currentIndex + 1].id));
    const tabs = [...document.querySelectorAll('[data-detail-tab]')];
    const selectTab = tab => {
        tabs.forEach(item => {
            const selected = item === tab;
            item.setAttribute('aria-selected', String(selected));
            item.tabIndex = selected ? 0 : -1;
            document.getElementById('panel-' + item.dataset.detailTab).hidden = !selected;
        });
    };
    tabs.forEach((tab, index) => {
        tab.addEventListener('click', () => selectTab(tab));
        tab.addEventListener('keydown', event => {
            if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
            event.preventDefault();
            const next = event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1 : (index + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length;
            selectTab(tabs[next]); tabs[next].focus();
        });
    });
}

function renderDecisionForm(finding) {
    const actions = finding.allowed_actions || [];
    const needsAck = (finding.recommendation !== 'certify' || finding.mandatory_human_review) && actions.includes('certify');
    
    return `
        <div class="decision-form">
            <p class="eyebrow">YOUR DECISION</p><h3>Complete this review</h3><p class="help-text">Record a reason. Access changes follow the approved remediation workflow.</p>
            <form id="decision-form">
                <div class="form-group">
                    <label>Action</label>
                    <div class="radio-group">
                        ${actions.includes('certify') ? `
                            <div class="radio-option">
                                <input type="radio" id="action-certify" name="action" value="certify" required>
                                <label for="action-certify">Certify</label>
                            </div>
                        ` : ''}
                        ${actions.includes('revoke') ? `
                            <div class="radio-option">
                                <input type="radio" id="action-revoke" name="action" value="revoke" required>
                                <label for="action-revoke">Revoke</label>
                            </div>
                        ` : ''}
                        ${actions.includes('acknowledge') ? `
                            <div class="radio-option">
                                <input type="radio" id="action-acknowledge" name="action" value="acknowledge" required>
                                <label for="action-acknowledge">Acknowledge</label>
                            </div>
                        ` : ''}
                    </div>
                </div>
                
                <div class="form-group">
                    <label for="decision-reason">Reason (8-2000 characters)</label>
                    <textarea 
                        id="decision-reason" 
                        name="reason" 
                        required 
                        minlength="8" 
                        maxlength="2000"
                        placeholder="Enter your justification for this decision..."
                    ></textarea>
                </div>
                
                ${needsAck ? `
                    <div class="form-group">
                        <div class="checkbox-group">
                            <input type="checkbox" id="acknowledge-risk" name="acknowledge_risk" value="true">
                            <label for="acknowledge-risk">
                                I acknowledge the recorded risk before certifying this access
                            </label>
                        </div>
                    </div>
                ` : ''}
                
                <button type="submit">Record decision <span aria-hidden="true">-&gt;</span></button>
                <div id="decision-error" class="error" role="alert" aria-live="polite"></div>
            </form>
        </div>
    `;
}

function attachFindingHandlers(finding) {
    // Decision form
    const decisionForm = document.getElementById('decision-form');
    if (decisionForm) {
        decisionForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            await submitDecision(finding);
        });
    }
    
    // Retry remediation
    const retryBtn = document.getElementById('retry-remediation-btn');
    if (retryBtn) {
        retryBtn.addEventListener('click', async () => {
            try {
                showLoading();
                await api.retryRemediation(finding.remediation.id);
                showLoading(false);
                notify('Retry processed. The latest verification status is shown below.');
                await loadFinding(finding.id);
            } catch (error) {
                showLoading(false);
                alert('Failed to retry remediation: ' + error.message);
            }
        });
    }
}

async function submitDecision(finding) {
    try {
        clearError('decision-error');
        
        const form = document.getElementById('decision-form');
        const formData = new FormData(form);
        
        const decision = {
            action: formData.get('action'),
            reason: formData.get('reason'),
            expected_version: finding.version,
            acknowledge_risk: formData.get('acknowledge_risk') === 'true'
        };
        
        // Validate
        if (!decision.action) {
            showError('decision-error', 'Please select an action');
            return;
        }
        
        if (!decision.reason || decision.reason.length < 8) {
            showError('decision-error', 'Reason must be at least 8 characters');
            return;
        }
        
        showLoading();
        
        const signature = JSON.stringify(decision);
        let pending = decisionRequests.get(finding.id);
        if (!pending || pending.signature !== signature) { pending = { signature, key: generateIdempotencyKey() }; decisionRequests.set(finding.id, pending); }
        await api.makeDecision(finding.id, decision, pending.key);
        decisionDrafts.delete(finding.id);
        decisionRequests.delete(finding.id);
        const refreshedCampaign = await api.getCampaign(finding.campaign_id);
        state.currentCampaign = refreshedCampaign;
        state.allFindings = refreshedCampaign.findings;
        state.filteredFindings = refreshedCampaign.findings;
        
        showLoading(false);
        notify('Decision recorded. You can continue to the next finding.');
        renderCampaignDetail();
        document.getElementById('finding-content').innerHTML = ''; // Do not re-save the submitted draft.
        
        // Reload finding
        await loadFinding(finding.id);
    } catch (error) {
        showLoading(false);
        
        if (error.status === 409) {
            if (error.code === 'version_conflict') {
                alert('This finding was updated by someone else. Please refresh and try again.');
                await loadFinding(finding.id);
            } else {
                showError('decision-error', error.message);
            }
        } else if (error.status === 422) {
            showError('decision-error', error.message);
        } else {
            showError('decision-error', error.message || 'Failed to submit decision');
        }
    }
}

// Audit
async function loadAudit() {
    const select = document.getElementById('audit-campaign-select');
    const campaignId = select.value;
    
    if (!campaignId) {
        showError('audit-error', 'Please select a campaign');
        return;
    }
    
    try {
        showLoading();
        clearError('audit-error');
        
        const data = await api.getAudit(campaignId);
        renderAudit(data);
        showLoading(false);
    } catch (error) {
        showLoading(false);
        showError('audit-error', error.message || 'Failed to load audit log');
    }
}

function renderAudit(data) {
    const container = document.getElementById('audit-content');
    
    if (data.events.length === 0) {
        container.innerHTML = '<p>No audit events found.</p>';
        return;
    }
    
    const integrityBadge = data.integrity 
        ? '<span class="badge" style="background: var(--color-success);">Verified</span>'
        : '<span class="badge" style="background: var(--color-danger);">Integrity Failure</span>';
    
    const html = `
        <div style="margin-bottom: 1rem;">
            <strong>Chain Integrity:</strong> ${integrityBadge}
        </div>
        <div class="audit-table">
            <table>
                <thead>
                    <tr>
                        <th>Sequence</th>
                        <th>Timestamp</th>
                        <th>Actor</th>
                        <th>Action</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
                    ${data.events.map(event => `
                        <tr>
                            <td>${event.seq}</td>
                            <td>${formatDate(event.timestamp)}</td>
                            <td>${escapeHtml(event.actor_id)}</td>
                            <td>${escapeHtml(event.action)}</td>
                            <td><code style="font-size: 0.75rem;">${escapeHtml(JSON.stringify(event.data).substring(0, 100))}...</code></td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `;
    
    container.innerHTML = html;
}

// Initialize

// ---------------------------------------------------------------------------
// Source environment
//
// A live view of what the connector reports right now. Everything rendered
// here comes from the normalized scan, so it stays source independent: generic
// entitlement IDs and grant-path kinds, never a native group name.
// ---------------------------------------------------------------------------

let environmentTimer = null;
let environmentRequest = null;
let environmentRenderKey = null;
const pendingStarts = new Map();
const campaignNames = new Map();
const environmentActions = new Set();
const activeRunStates = ['queued', 'scanning', 'validating', 'reviewing'];

function stopEnvironmentPolling() {
    if (environmentTimer !== null) {
        clearInterval(environmentTimer);
        environmentTimer = null;
    }
}

function environmentVisible() {
    const view = document.getElementById('environment-view');
    return view !== null && !view.classList.contains('hidden');
}

async function loadEnvironment({ quiet = false, navigate = true } = {}) {
    const session = state.sessionVersion;
    if (environmentRequest === session || state.user?.role !== 'admin') return;
    environmentRequest = session;
    if (!quiet) { showLoading(true); clearError('environment-error'); }
    try {
        // Status reads never contact a source or launch a scan.
        const data = await api.request('/api/environments');
        if (session !== state.sessionVersion) return;
        state.environment = data;
        renderEnvironment(data);
        if (navigate) showView('environment-view');
        if (environmentVisible() && environmentTimer === null) {
            environmentTimer = setInterval(() => {
                if (environmentVisible()) loadEnvironment({ quiet: true, navigate: false });
            }, 3000);
        }
    } catch (error) {
        if (session === state.sessionVersion) showError('environment-error', error.message || 'Unable to load environments.');
    } finally {
        if (session === state.sessionVersion) {
            environmentRequest = null;
            if (!quiet) showLoading(false);
        }
    }
}

async function startEnvironmentReview(source) {
    const session = state.sessionVersion;
    if (environmentActions.has(source)) return;
    let request = pendingStarts.get(source);
    if (!request) {
        const name = (campaignNames.get(source) ?? `${source} access review`).trim();
        if (!name) { showError('environment-error', 'Enter a campaign name.'); return; }
        request = { name, key: generateIdempotencyKey() };
        pendingStarts.set(source, request);
    }
    environmentActions.add(source);
    clearError('environment-error');
    if (state.environment) renderEnvironment(state.environment);
    try {
        await api.request(`/api/environments/${encodeURIComponent(source)}/campaign-runs`, {
            method: 'POST', headers: { 'Idempotency-Key': request.key }, body: JSON.stringify({ name: request.name })
        });
        if (session !== state.sessionVersion) return;
        pendingStarts.delete(source);
    } catch (error) {
        if (session !== state.sessionVersion) return;
        // A network/5xx failure can hide an accepted job: retain its exact key/body.
        if (error.status && error.status < 500) pendingStarts.delete(source);
        showError('environment-error', error.message || 'Connection interrupted. Retry submission safely with the same request.');
    } finally {
        if (session === state.sessionVersion) {
            environmentActions.delete(source);
            if (state.environment) renderEnvironment(state.environment);
            await loadEnvironment({ quiet: true, navigate: false });
        }
    }
}

async function retryCampaignRun(runId, source) {
    const session = state.sessionVersion;
    if (environmentActions.has(source)) return;
    environmentActions.add(source);
    clearError('environment-error');
    if (state.environment) renderEnvironment(state.environment);
    try {
        await api.request(`/api/campaign-runs/${encodeURIComponent(runId)}/retry`, { method: 'POST' });
    } catch (error) {
        if (session === state.sessionVersion) showError('environment-error', error.message);
    } finally {
        if (session === state.sessionVersion) {
            environmentActions.delete(source);
            await loadEnvironment({ quiet: true, navigate: false });
        }
    }
}

function renderEnvironment(data) {
    document.getElementById('env-freshness').textContent =
        'Inventory is a saved observation. Start access review requests a fresh scan. Status updates do not scan the target.';
    const container = document.getElementById('environment-content');
    // Status polls usually change only generated_at. Keep the actual controls
    // (and keyboard focus) in place when the displayed state is unchanged.
    const renderKey = JSON.stringify([data.sources, [...pendingStarts], [...environmentActions]]);
    if (renderKey === environmentRenderKey) return;
    environmentRenderKey = renderKey;
    const focused = container.contains(document.activeElement) ? document.activeElement : null;
    const focusKey = focused?.getAttribute('data-focus-key');
    const selection = focused?.tagName === 'INPUT' ? [focused.selectionStart, focused.selectionEnd] : null;
    const expanded = new Set([...container.querySelectorAll('details[data-details-key]')]
        .filter(details => details.open).map(details => details.dataset.detailsKey));
    const modes = { simulated: 'Simulated source', captured_fixture: 'Captured fixture · read only', live: 'Live connector (configured)', unknown: 'Transport not specified' };
    const labels = { queued: 'Queued', scanning: 'Scanning environment', validating: 'Validating evidence', reviewing: 'Reviewing access', completed: 'Review ready', failed: 'Run failed', blocked: 'Review blocked', never_scanned: 'Not scanned yet', last_known: 'Last-known inventory' };
    const runStages = [
        ['queued', 'Queued', 'Run accepted'],
        ['scanning', 'Scanning', 'Fresh source evidence'],
        ['validating', 'Validating', 'Quality and correlation checks'],
        ['reviewing', 'Reviewing', 'Policy and case assessment'],
        ['completed', 'Review ready', 'Findings available']
    ];
    const runStageRail = run => {
        const events = run.events || [];
        const lastStage = [...events].reverse().find(event => runStages.some(stage => stage[0] === event.state));
        const activeKey = run.state === 'completed' ? 'completed' : lastStage?.state || run.state;
        const activeIndex = Math.max(0, runStages.findIndex(stage => stage[0] === activeKey));
        return `<div class="run-stage-rail" data-state="${escapeHtml(run.state)}">${runStages.map(([key, label, detail], index) => { const state = run.state === 'completed' || index < activeIndex ? 'complete' : index === activeIndex ? 'current' : 'pending'; const event = events.find(item => item.state === key); return `<div class="run-stage ${state}"><span class="run-stage-marker">${state === 'complete' ? '✓' : index + 1}</span><div><strong>${label}</strong><small>${detail}</small>${event ? `<time>${escapeHtml(formatDate(event.timestamp))}</time>` : ''}</div></div>${index < runStages.length - 1 ? '<span class="run-stage-connector" aria-hidden="true"></span>' : ''}`; }).join('')}</div>`;
    };
    container.innerHTML = data.sources.length ? data.sources.map((source, index) => {
        const run = source.run;
        const busy = environmentActions.has(source.source) || (run && activeRunStates.includes(run.state));
        const inv = source.inventory;
        const name = campaignNames.get(source.source) ?? `${source.source} access review`;
        const review = source.latest_campaign?.review;
        const rows = inv?.accounts.map(account => `<tr>
            <td>${escapeHtml(account.username)}</td><td>${account.enabled ? 'Enabled' : 'Disabled'}</td>
            <td>${escapeHtml(account.account_type)}</td><td>${account.entitlements.length}</td>
            <td>${account.direct}</td><td>${account.inherited}</td>
            <td>${account.entitlements.map(escapeHtml).join(', ') || 'None'}</td></tr>`).join('') || '';
        return `<article class="campaign-card environment-card" data-source="${escapeHtml(source.source)}">
            <h3>${escapeHtml(source.name)}</h3>
            <p class="help-text">${escapeHtml(source.source)} · ${escapeHtml(modes[source.mode] || modes.unknown)}</p>
            <p role="status">${escapeHtml(labels[source.status] || source.status)}</p>
            ${inv ? `<p>Observed ${escapeHtml(formatDate(inv.scanned_at))} · ${inv.complete ? 'Complete within declared scope' : 'Partial evidence'}<br>
                <small>Scan: ${escapeHtml(inv.scan_id)} · Mapping: ${escapeHtml(inv.mapping_version)}</small></p>
                <div class="summary-cards">
                <div class="summary-card"><h4>Accounts</h4><p>${inv.counts.accounts}</p></div>
                <div class="summary-card"><h4>Assignments</h4><p>${inv.counts.assignments}</p></div>
                <div class="summary-card"><h4>Entitlements</h4><p>${inv.counts.entitlements}</p></div>
                <div class="summary-card"><h4>Accounts without access</h4><p>${inv.counts.unassigned_accounts}</p></div></div>
                <details data-details-key="${escapeHtml(source.source)}:inventory"><summary data-focus-key="${escapeHtml(source.source)}:inventory">Inspect observed accounts and access</summary><div class="env-table-wrap"><table class="env-table">
                <thead><tr><th>Account</th><th>State</th><th>Type</th><th>Entitlements</th><th>Direct</th><th>Inherited</th><th>Held access</th></tr></thead>
                <tbody>${rows}</tbody></table></div></details>` : '<p>No inventory has been observed. Counts are unknown until a scan completes.</p>'}
            ${source.setup_error ? `<p class="warning-banner">${escapeHtml(source.setup_error)}</p>` : ''}
            <form class="start-review-form">
                <label for="campaign-name-${index}">Campaign name</label>
                <input id="campaign-name-${index}" data-focus-key="${escapeHtml(source.source)}:name" name="campaignName" value="${escapeHtml(name)}" maxlength="2000" required ${busy || pendingStarts.has(source.source) ? 'disabled' : ''}>
                <button type="submit" data-focus-key="${escapeHtml(source.source)}:start" ${busy || !source.can_start ? 'disabled' : ''}>${pendingStarts.has(source.source) ? 'Retry submission' : 'Start access review'}</button>
            </form>
            ${run ? `<div class="run-progress" aria-live="polite">
                <div class="run-progress-heading"><div><p class="eyebrow">CAMPAIGN RUN</p><h3>${escapeHtml(run.name)}</h3></div><span class="run-state ${escapeHtml(run.state)}"><i aria-hidden="true"></i>${escapeHtml(labels[run.state] || run.state)}</span></div>
                <div class="run-progress-meta"><span>Attempt ${run.attempts} of 3</span><span>${run.scan_id ? 'Snapshot accepted' : 'Waiting for snapshot'}</span></div>
                ${runStageRail(run)}
                <details data-details-key="${escapeHtml(source.source)}:progress"><summary data-focus-key="${escapeHtml(source.source)}:progress">Recorded progress</summary><ol>${(run.events || []).map(event => `<li>${escapeHtml(formatDate(event.timestamp))}: ${escapeHtml(labels[event.state] || event.state)}${event.message ? ' — ' + escapeHtml(event.message) : ''}</li>`).join('')}</ol></details>
                ${run.error ? `<p class="error">${escapeHtml(run.error)}</p>` : ''}
                ${run.retry_guidance ? `<p>${escapeHtml(run.retry_guidance)}</p>` : ''}
                ${run.can_retry ? `<button type="button" data-focus-key="${escapeHtml(source.source)}:retry" data-retry="${escapeHtml(run.id)}" ${busy ? 'disabled' : ''}>Retry run</button>` : ''}
                ${run.campaign_id ? `<button type="button" data-focus-key="${escapeHtml(source.source)}:findings" data-open-campaign="${escapeHtml(run.campaign_id)}">Open review findings</button>` : ''}
            </div>` : ''}
            ${source.latest_campaign ? `<p>Latest campaign: <button type="button" class="secondary" data-focus-key="${escapeHtml(source.source)}:latest" data-open-campaign="${escapeHtml(source.latest_campaign.id)}">${escapeHtml(source.latest_campaign.name)}</button></p>` : ''}
            ${review ? `<p class="help-text">Latest campaign: ${review.cases - review.fallback_cases} AI-reviewed cases; ${review.fallback_cases} rules fallbacks. Human decisions are still required.</p>` : ''}
        </article>`;
    }).join('') : '<p>No environments configured. Add a connector and input references to the server configuration, or start an empty simulated demo.</p>';
    container.querySelectorAll('.environment-card').forEach(card => {
        const source = card.dataset.source;
        card.querySelectorAll('details[data-details-key]').forEach(details => {
            details.open = expanded.has(details.dataset.detailsKey);
        });
        card.querySelector('input').addEventListener('input', event => campaignNames.set(source, event.target.value));
        card.querySelector('form').addEventListener('submit', event => { event.preventDefault(); startEnvironmentReview(source); });
        card.querySelectorAll('[data-open-campaign]').forEach(button => button.addEventListener('click', () => loadCampaign(button.dataset.openCampaign)));
        card.querySelectorAll('[data-retry]').forEach(button => button.addEventListener('click', () => retryCampaignRun(button.dataset.retry, source)));
    });
    if (focusKey) {
        const replacement = [...container.querySelectorAll('[data-focus-key]')]
            .find(element => element.getAttribute('data-focus-key') === focusKey);
        if (replacement && !replacement.disabled) {
            replacement.focus({ preventScroll: true });
            if (selection) replacement.setSelectionRange(...selection);
        }
    }
}

document.addEventListener('DOMContentLoaded', () => {
    // Login form
    document.getElementById('login-form').addEventListener('submit', (e) => {
        e.preventDefault();
        const token = document.getElementById('token-input').value;
        login(token);
    });
    
    // Logout button
    document.getElementById('logout-btn').addEventListener('click', () => {
        logout();
    });
    
    // Navigation
    document.querySelectorAll('.nav-btn').forEach(btn => {
        btn.addEventListener('click', async () => {
            const view = btn.dataset.view;
            if (view === 'campaigns') {
                loadCampaigns();
            } else if (view === 'environment') {
                loadEnvironment();
            } else if (view === 'audit') {
                showView('audit-view');
                try { state.campaigns = (await api.getCampaigns()).campaigns; }
                catch (error) { showError('audit-error', error.message); return; }
                // Populate campaign select
                const select = document.getElementById('audit-campaign-select');
                select.innerHTML = '<option value="">Select a campaign...</option>' +
                    state.campaigns.map(c => `<option value="${escapeHtml(c.id)}">${escapeHtml(c.name)}</option>`).join('');
            }
        });
    });
    
    // Campaign actions
    document.getElementById('refresh-campaigns-btn').addEventListener('click', loadCampaigns);
    document.getElementById('back-to-campaigns-btn').addEventListener('click', loadCampaigns);
    document.getElementById('back-to-findings-btn').addEventListener('click', () => {
        if (state.currentCampaign) {
            renderCampaignDetail();
            showView('campaign-detail-view');
        } else {
            loadCampaigns();
        }
    });
    
    // Filters
    document.getElementById('finding-search').addEventListener('input', applyFilters);
    document.getElementById('finding-sort').addEventListener('change', applyFilters);
    document.getElementById('clear-filters-btn').addEventListener('click', () => {
        for (const id of ['finding-search', 'risk-filter', 'status-filter']) document.getElementById(id).value = '';
        applyFilters();
    });
    document.getElementById('risk-filter').addEventListener('change', applyFilters);
    document.getElementById('status-filter').addEventListener('change', applyFilters);
    
    // Environment
    document.getElementById('refresh-environment-btn').addEventListener('click', () => loadEnvironment());
    // Audit
    document.getElementById('load-audit-btn').addEventListener('click', loadAudit);
});
