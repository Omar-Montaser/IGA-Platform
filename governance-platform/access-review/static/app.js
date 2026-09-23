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
    filteredFindings: []
};

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
                      'user-name', 'user-role', 'campaign-name', 'environment-content', 'environment-error', 'env-freshness']) {
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
        || document.querySelector(`.nav-btn[data-view="${viewId.replace(/-view$/, '')}"]`);
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
    
    if (state.campaigns.length === 0) {
        container.innerHTML = '<p>No campaigns found.</p>';
        return;
    }
    
    const html = state.campaigns.map(campaign => `
        <div class="campaign-card" data-campaign-id="${escapeHtml(campaign.id)}" 
             role="article" tabindex="0" aria-label="Campaign: ${escapeHtml(campaign.name)}">
            <h3>${escapeHtml(campaign.name)}</h3>
            <div class="campaign-meta">
                <span><strong>Source:</strong> ${escapeHtml(campaign.source)}</span>
                <span><strong>Created:</strong> ${formatDate(campaign.created_at)}</span>
                <span><strong>Total Findings:</strong> ${campaign.summary.total}</span>
                <span><strong>Pending:</strong> ${campaign.summary.pending}</span>
                <span><strong>Critical:</strong> <span class="badge critical">${campaign.summary.critical}</span></span>
                <span><strong>High:</strong> <span class="badge high">${campaign.summary.high}</span></span>
                ${campaign.metadata?.review ? `<span><strong>AI-reviewed cases:</strong> ${campaign.metadata.review.cases - campaign.metadata.review.fallback_cases} / ${campaign.metadata.review.cases}</span>
                <span><strong>Non-AI fallbacks:</strong> ${campaign.metadata.review.fallback_cases}</span>` : ''}
            </div>
            ${campaign.warnings.length > 0 ? `
                <div style="margin-top: 1rem; color: var(--color-warning);">
                    ⚠ ${campaign.warnings.length} warning(s)
                </div>
            ` : ''}
        </div>
    `).join('');
    
    container.innerHTML = html;
    
    // Add click handlers
    container.querySelectorAll('.campaign-card').forEach(card => {
        const clickHandler = () => {
            const campaignId = card.dataset.campaignId;
            loadCampaign(campaignId);
        };
        card.addEventListener('click', clickHandler);
        card.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') clickHandler();
        });
    });
}

// Campaign detail
async function loadCampaign(campaignId) {
    try {
        showLoading();
        clearError('campaign-detail-error');
        
        const campaign = await api.getCampaign(campaignId);
        state.currentCampaign = campaign;
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
                alert('Remediation processing started. Refresh to see updates.');
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
    
    // Findings
    applyFilters();
}

function applyFilters() {
    const riskFilter = document.getElementById('risk-filter').value;
    const statusFilter = document.getElementById('status-filter').value;
    
    state.filteredFindings = state.allFindings.filter(finding => {
        if (riskFilter && finding.risk_level !== riskFilter) return false;
        if (statusFilter && finding.status !== statusFilter) return false;
        return true;
    });
    
    renderFindings();
}

function renderFindings() {
    const container = document.getElementById('findings-list');
    
    if (state.filteredFindings.length === 0) {
        container.innerHTML = '<p>No findings match the selected filters.</p>';
        return;
    }
    
    const html = state.filteredFindings.map(finding => `
        <div class="finding-card" data-finding-id="${escapeHtml(finding.id)}"
             role="article" tabindex="0" aria-label="Finding for ${escapeHtml(finding.identity_name)}">
            <h3>${escapeHtml(finding.identity_name)} - ${escapeHtml(finding.entitlement_name)}</h3>
            <div class="finding-meta">
                <span><strong>Risk:</strong> <span class="badge ${finding.risk_level}">${finding.risk_level}</span></span>
                <span><strong>Status:</strong> <span class="badge ${finding.status}">${finding.status.replace(/_/g, ' ')}</span></span>
                <span><strong>Policy:</strong> ${escapeHtml(finding.policy_result)}</span>
                <span><strong>Assessment:</strong> ${escapeHtml(finding.recommended_action || finding.recommendation)}</span>
                ${finding.reviewer_id ? `<span><strong>Reviewer:</strong> ${escapeHtml(finding.reviewer_id)}</span>` : ''}
            </div>
            ${finding.mandatory_human_review ? `
                <div style="margin-top: 0.5rem; color: var(--color-danger);">
                    ⚠ Mandatory human review: ${(finding.human_review_reasons || []).map(reason => escapeHtml(reason.replace(/_/g, ' '))).join(', ')}
                </div>
            ` : ''}
            ${finding.decision_blockers && finding.decision_blockers.length > 0 ? `
                <div style="margin-top: 0.5rem; color: var(--color-danger);">
                    ⚠ Decision blocked: ${finding.decision_blockers.length} issue(s)
                </div>
            ` : ''}
        </div>
    `).join('');
    
    container.innerHTML = html;
    
    // Add click handlers
    container.querySelectorAll('.finding-card').forEach(card => {
        const clickHandler = () => {
            const findingId = card.dataset.findingId;
            loadFinding(findingId);
        };
        card.addEventListener('click', clickHandler);
        card.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') clickHandler();
        });
    });
}

// Finding detail
async function loadFinding(findingId) {
    try {
        showLoading();
        clearError('finding-error');
        
        const finding = await api.getFinding(findingId);
        state.currentFinding = finding;
        
        renderFindingDetail();
        showView('finding-detail-view');
        showLoading(false);
    } catch (error) {
        showLoading(false);
        showError('finding-error', error.message || 'Failed to load finding');
    }
}

function renderFindingDetail() {
    const finding = state.currentFinding;
    const container = document.getElementById('finding-content');
    
    let html = '';
    
    // Basic info
    html += `
        <div class="finding-detail-section">
            <h3>Finding Information</h3>
            <div class="detail-grid">
                <div class="detail-item">
                    <span class="detail-label">Identity</span>
                    <span class="detail-value">${escapeHtml(finding.identity_name)}</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Username</span>
                    <span class="detail-value">${escapeHtml(finding.username)}</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Department</span>
                    <span class="detail-value">${escapeHtml(finding.department)}</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Role</span>
                    <span class="detail-value">${escapeHtml(finding.role)}</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Employment Status</span>
                    <span class="detail-value">${escapeHtml(finding.employment_status)}</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Entitlement</span>
                    <span class="detail-value">${escapeHtml(finding.entitlement_name)}</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Sensitivity</span>
                    <span class="detail-value">${escapeHtml(finding.sensitivity)}</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Privileged</span>
                    <span class="detail-value">${finding.privileged === null ? 'Unknown' : finding.privileged ? 'Yes' : 'No'}</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Risk Score</span>
                    <span class="detail-value">${finding.risk_score}/100</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Risk Level</span>
                    <span class="detail-value"><span class="badge ${finding.risk_level}">${finding.risk_level}</span></span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Policy Result</span>
                    <span class="detail-value">${escapeHtml(finding.policy_result)}</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Independent Assessment</span>
                    <span class="detail-value">${escapeHtml(finding.recommended_action || finding.recommendation)}</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Status</span>
                    <span class="detail-value"><span class="badge ${finding.status}">${finding.status.replace(/_/g, ' ')}</span></span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Version</span>
                    <span class="detail-value">${finding.version}</span>
                </div>
            </div>
        </div>
    `;
    
    // Signals
    if (finding.signals && finding.signals.length > 0) {
        html += `
            <div class="finding-detail-section">
                <h3>Risk Signals</h3>
                <ul class="signals-list">
                    ${finding.signals.map(signal => `
                        <li class="signal-item">
                            <strong>${escapeHtml(signal.code)} (${signal.points} points)</strong>
                            <span>${escapeHtml(signal.message)}</span>
                        </li>
                    `).join('')}
                </ul>
            </div>
        `;
    }
    
    // Peer information
    if (finding.peer && finding.peer.available) {
        html += `
            <div class="finding-detail-section">
                <h3>Peer Analysis</h3>
                <div class="detail-grid">
                    <div class="detail-item">
                        <span class="detail-label">Peer Count</span>
                        <span class="detail-value">${finding.peer.count}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Holders</span>
                        <span class="detail-value">${finding.peer.holders}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Ratio</span>
                        <span class="detail-value">${(finding.peer.ratio * 100).toFixed(1)}%</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Reason</span>
                        <span class="detail-value">${escapeHtml(finding.peer.reason)}</span>
                    </div>
                </div>
            </div>
        `;
    }
    
    if (finding.mandatory_human_review) {
        html += `
            <div class="finding-detail-section" role="alert">
                <h3>Mandatory Human Review</h3>
                <p>${(finding.human_review_reasons || []).map(reason => escapeHtml(reason.replace(/_/g, ' '))).join(', ')}</p>
            </div>
        `;
    }

    // Person-level assessment generated during campaign creation
    if ((finding.evidence_gaps || []).length) {
        html += `<div class="finding-detail-section"><h3>Observed Evidence Limits</h3><ul>
            ${finding.evidence_gaps.map(gap => `<li>${escapeHtml(gap)}</li>`).join('')}</ul></div>`;
    }
    if (finding.review_evidence) {
        html += `<div class="finding-detail-section"><details><summary>Source evidence for this access</summary>
            <pre>${escapeHtml(JSON.stringify(finding.review_evidence, null, 2))}</pre></details></div>`;
    }
    if (finding.explanation) {
        html += `
            <div class="explanation-section">
                <div class="explanation-header">
                    <h3>Independent Case Assessment</h3>
                    <div class="explanation-provider">
                        Provider: <span class="badge">${escapeHtml(finding.explanation.provider)}</span>
                        ${finding.explanation.model ? ' Model: ' + escapeHtml(finding.explanation.model) : ''}
                        ${finding.explanation.attempted_provider ? ' (attempted: ' + escapeHtml(finding.explanation.attempted_provider) + ')' : ''}
                        ${finding.explanation.status === 'fallback' ? ' (fallback: ' + escapeHtml(finding.explanation.fallback_reason) + ')' : ''}
                    </div>
                </div>
                <div class="explanation-text">${escapeHtml(finding.explanation.reasoning || '')}</div>
                <p><strong>Model self-reported confidence (not a measured probability):</strong> ${finding.explanation.status === 'ready' && typeof finding.explanation.confidence === 'number' ? (finding.explanation.confidence * 100).toFixed(0) + '%' : 'Not applicable — non-AI fallback'}</p>
                ${finding.item_assessment ? `<p><strong>This access item:</strong> ${escapeHtml(finding.item_assessment.action)} — ${escapeHtml(finding.item_assessment.reasoning)}</p>
                <p><strong>Evidence references:</strong> ${(finding.item_assessment.evidence_refs || []).map(escapeHtml).join(', ')}</p>` : ''}
                ${(finding.explanation.open_questions || []).length ? `<p><strong>Open questions:</strong> ${(finding.explanation.open_questions || []).map(escapeHtml).join('; ')}</p>` : ''}
                ${(finding.explanation.missing_evidence || []).length ? `<p><strong>Missing evidence:</strong> ${(finding.explanation.missing_evidence || []).map(escapeHtml).join('; ')}</p>` : ''}
            </div>
        `;
    }
    
    // Decision form
    if (finding.can_decide) {
        html += renderDecisionForm(finding);
    } else if (finding.decision_blockers && finding.decision_blockers.length > 0) {
        html += `
            <div class="finding-detail-section">
                <h3>Decision Blocked</h3>
                <div class="blockers-list">
                    <p>The following issues prevent making a decision:</p>
                    <ul>
                        ${finding.decision_blockers.map(blocker => `<li>${escapeHtml(blocker)}</li>`).join('')}
                    </ul>
                </div>
            </div>
        `;
    }
    
    // Remediation info
    if (finding.remediation) {
        html += `
            <div class="finding-detail-section">
                <h3>Remediation Status</h3>
                <div class="detail-grid">
                    <div class="detail-item">
                        <span class="detail-label">Request ID</span>
                        <span class="detail-value">${escapeHtml(finding.remediation.id)}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">State</span>
                        <span class="detail-value"><span class="badge ${finding.remediation.state}">${finding.remediation.state}</span></span>
                    </div>
                    ${finding.remediation.last_error ? `
                        <div class="detail-item" style="grid-column: 1 / -1;">
                            <span class="detail-label">Error</span>
                            <span class="detail-value" style="color: var(--color-danger);">${escapeHtml(finding.remediation.last_error)}</span>
                        </div>
                    ` : ''}
                </div>
                ${state.user.role === 'admin' && (finding.remediation.state === 'failed' || finding.remediation.state === 'verification_failed') ? `
                    <button type="button" id="retry-remediation-btn" style="margin-top: 1rem;">
                        Retry Remediation
                    </button>
                ` : ''}
            </div>
        `;
    }
    
    container.innerHTML = html;
    
    // Attach event handlers
    attachFindingHandlers(finding);
}

function renderDecisionForm(finding) {
    const actions = finding.allowed_actions || [];
    const needsAck = (finding.recommendation !== 'certify' || finding.mandatory_human_review) && actions.includes('certify');
    
    return `
        <div class="decision-form">
            <h3>Make Decision</h3>
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
                
                <button type="submit">Submit Decision</button>
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
                alert('Retry requested. Refresh to see updates.');
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
        
        const idempotencyKey = generateIdempotencyKey();
        await api.makeDecision(finding.id, decision, idempotencyKey);
        const refreshedCampaign = await api.getCampaign(finding.campaign_id);
        state.currentCampaign = refreshedCampaign;
        state.allFindings = refreshedCampaign.findings;
        state.filteredFindings = refreshedCampaign.findings;
        
        showLoading(false);
        alert('Decision recorded successfully');
        
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
                <p><strong>${escapeHtml(run.name)}:</strong> ${escapeHtml(labels[run.state] || run.state)} · Attempt ${run.attempts} of 3</p>
                <p class="help-text">Queued → Scanning → Validating → Reviewing → Review ready</p>
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
    document.getElementById('risk-filter').addEventListener('change', applyFilters);
    document.getElementById('status-filter').addEventListener('change', applyFilters);
    
    // Environment
    document.getElementById('refresh-environment-btn').addEventListener('click', () => loadEnvironment());
    // Audit
    document.getElementById('load-audit-btn').addEventListener('click', loadAudit);
});
