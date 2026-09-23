# IGA Platform Feature Comparison & Roadmap

## Executive Summary

This document compares the current IGA-Platform prototype with commercial IGA solutions (RSA Governance & Lifecycle, SailPoint, Saviynt, Lumos) and provides a roadmap for closing feature gaps.

**Current Status:** ✅ **Strong foundation** with access review campaigns, policy evaluation, and remediation  
**Gap:** Missing continuous governance dashboards, identity lifecycle automation, and always-on visibility  
**Recommendation:** Complete and validate the environment-to-campaign workflow before broader identity and access dashboards.

**Implementation update (2026-09-23):** Environment visibility already existed
through an admin scan view; the earlier claim that all visibility was confined
to campaigns was incorrect. The current implementation makes Environment the
admin landing page, lists configured sources without scanning, retains inventory
snapshots, and starts durable access-review runs with progress, recovery and
campaign links. This is the immediate prerequisite to the broader dashboard
phases below. Examples later in this roadmap are proposals, not executable setup
instructions; use `SETUP-AND-RUN-GUIDE.md` and the Module 4 API contract.

---

## What Commercial IGA Platforms Provide

### 1. **Identity Dashboard / Unified Access Graph**
Shows the **current state** of all identities and their access in real-time.

**What users see:**
- **User Directory**: List of all users with their roles, departments, status
- **Access Matrix**: Who has access to what applications/entitlements
- **Identity Details Page**: Click a user → see all their access, group memberships, entitlements
- **Application Directory**: List of all apps with who has access to each
- **Search & Filter**: Find users by department, role, access, risk level

**RSA G&L shows:**
- "Who has access? How did they get it? Should they still have it?"
- Real-time visibility across all environments
- Every identity (human and non-human) in one view

**Your Platform Currently:**
- ❌ No identity dashboard
- ❌ No user directory view
- ❌ No access matrix
- ✅ Environment view exposes configured sources and observed account/access inventory outside campaigns; durable runs connect fresh discovery to review findings.

---

### 2. **Lifecycle Management Dashboard**
Tracks joiner-mover-leaver (JML) workflows.

**What users see:**
- **Pending Onboarding**: New hires awaiting access provisioning
- **Role Changes**: Employees changing departments/roles
- **Offboarding Queue**: Employees leaving, access needs removal
- **Automated Workflows**: Status of auto-provisioning/deprovisioning

**RSA G&L provides:**
- Automated JML workflows
- Closed-loop validation (verify access was actually granted/removed)
- Role-based access controls (RBAC)

**Your Platform Currently:**
- ❌ No JML automation
- ❌ No workflow dashboard
- ✅ Has manual lifecycle detection (lifecycle_restricted findings)
- ✅ Can remediate (remove access), but no auto-provisioning

---

### 3. **Risk & Analytics Dashboard**
Continuous risk monitoring and trend analysis.

**What users see:**
- **Risk Score**: Overall organization risk score
- **High-Risk Users**: Users with excessive/sensitive access
- **Anomalous Access**: Unusual permissions detected by AI
- **Segregation of Duties (SoD) Violations**: Toxic combinations (e.g., can create AND approve payments)
- **Trend Charts**: Risk over time, violations by department

**RSA G&L provides:**
- AI-driven risk analytics
- Real-time anomaly detection
- Risk trends over time
- SoD detection and enforcement

**Your Platform Currently:**
- ✅ Has risk scoring (per-finding)
- ✅ Has policy violation detection
- ❌ No overall risk dashboard
- ❌ No SoD detection
- ❌ No trending/analytics
- ✅ Risk is calculated during campaigns, not continuously

---

### 4. **Compliance & Audit Dashboard**
One-click audit reports and compliance tracking.

**What users see:**
- **Compliance Status**: SOX, HIPAA, GDPR, PCI-DSS compliance %
- **Audit Reports**: Pre-generated reports for auditors
- **Certification Status**: % of access reviews completed
- **Policy Violations**: Count of active violations
- **Audit Trail**: Searchable log of all access changes

**RSA G&L provides:**
- Customizable compliance reports (CJIS, HIPAA, SOX, PCI-DSS, NIST 800-53)
- Complete audit trails
- Compliance KPIs

**Your Platform Currently:**
- ✅ Has audit trail (per campaign)
- ✅ Has integrity hashing
- ✅ Can export audit data
- ❌ No compliance dashboard
- ❌ No pre-built compliance reports
- ❌ No KPI tracking

---

### 5. **Access Review Campaigns** ✅ YOU HAVE THIS!
Periodic certification of user access.

**What users see:**
- **Campaign List**: Active/completed review campaigns
- **Findings**: Access items to review (certify/revoke)
- **Filters**: By risk, policy, status, department
- **Decision Tracking**: Who approved/revoked what and when

**RSA G&L provides:**
- Automated access reviews
- Gamification (engagement scoring)
- AI-assisted pre-approval of low-risk access

**Your Platform Currently:**
- ✅ **YOU HAVE THIS!** Campaign-based reviews
- ✅ Finding list with filters
- ✅ Risk scoring per finding
- ✅ Decision recording with audit trail
- ✅ Remediation workflow
- ✅ AI-assisted explanations (optional)
- ✅ Evidence display (why they have access)

**This is your core strength!**

---

### 6. **Entitlement Catalog**
Directory of all permissions/entitlements across all systems.

**What users see:**
- **Entitlement List**: All permissions (e.g., "Finance: Approve Payments")
- **Risk Classification**: Which entitlements are high-risk/sensitive
- **Entitlement Details**: What the permission grants, who has it
- **Natural Language Descriptions**: Plain English explanation of technical permissions

**RSA G&L provides:**
- Entitlement visibility across all systems
- Risk classification
- Entitlement analytics

**Your Platform Currently:**
- ✅ Has entitlement data (in findings)
- ✅ Has entitlement mapping (connector)
- ❌ No entitlement catalog view
- ❌ No standalone entitlement search/browse

---

### 7. **Role Management**
Define and manage role-based access.

**What users see:**
- **Role Directory**: List of roles (e.g., "Software Engineer", "Finance Manager")
- **Role Definition**: What entitlements each role includes
- **Role Assignment**: Which users have which roles
- **Role Mining**: AI-suggested roles based on actual access patterns

**RSA G&L provides:**
- RBAC management
- Role mining and optimization
- Automated role assignment

**Your Platform Currently:**
- ✅ Uses roles from HR data
- ✅ Evaluates against role policies
- ❌ No role management UI
- ❌ No role mining
- ❌ No role assignment workflows

---

## Feature Gap Summary

| Feature Category | Commercial IGA | Your Platform | Gap Priority |
|-----------------|----------------|---------------|--------------|
| **Access Review Campaigns** | ✅ | ✅ **HAVE IT** | N/A - Core strength |
| **Identity Dashboard** | ✅ | ❌ Missing | 🔴 **HIGH** |
| **User Directory / Search** | ✅ | ❌ Missing | 🔴 **HIGH** |
| **Access Matrix View** | ✅ | ❌ Missing | 🟡 Medium |
| **Lifecycle (JML) Dashboard** | ✅ | ❌ Missing | 🟡 Medium |
| **Risk Dashboard** | ✅ | ⚠️ Partial | 🔴 **HIGH** |
| **SoD Detection** | ✅ | ❌ Missing | 🟢 Low (advanced) |
| **Compliance Dashboard** | ✅ | ⚠️ Partial | 🟡 Medium |
| **Entitlement Catalog** | ✅ | ❌ Missing | 🟡 Medium |
| **Role Management UI** | ✅ | ❌ Missing | 🟢 Low (data exists) |
| **Audit Trail** | ✅ | ✅ **HAVE IT** | N/A |
| **Remediation** | ✅ | ✅ **HAVE IT** | N/A |
| **AI-Assisted Reviews** | ✅ | ✅ **HAVE IT** | N/A |
| **Non-Human Identities** | ✅ | ✅ **HAVE IT** | N/A |

---

## Recommended Roadmap

### **Phase 1: Identity & Access Visibility** (3-4 weeks)
**Goal:** Show users their current identity landscape outside of campaigns.

#### 1.1 Identity Dashboard (Home Page)
```
┌─────────────────────────────────────────────────┐
│          IGA Platform Dashboard                 │
├─────────────────────────────────────────────────┤
│                                                 │
│  📊 OVERVIEW                                    │
│  ┌──────────┬──────────┬──────────┬──────────┐│
│  │   Users  │  Access  │ Critical │ Pending  ││
│  │    374   │  Assign. │   45     │   127    ││
│  └──────────┴──────────┴──────────┴──────────┘│
│                                                 │
│  ⚠️ TOP RISKS                                   │
│  • 41 employees left but still have access     │
│  • 8 restricted access violations              │
│  • 6 unlisted entitlements                     │
│                                                 │
│  📋 ACTIVE CAMPAIGNS                            │
│  • Q4 Access Review - 127 pending decisions    │
│  • Engineering Quarterly - Completed           │
│                                                 │
│  📈 TREND (Last 30 Days)                        │
│  • Violations: 48 → 55 (+14%)                  │
│  • Reviews Completed: 247                      │
│                                                 │
└─────────────────────────────────────────────────┘
```

**Implementation:**
- New route: `/dashboard`
- API endpoint: `GET /api/dashboard/summary`
- Shows:
  - Total users/accounts
  - Total access assignments
  - Critical findings count
  - Pending decisions count
  - Top risk categories
  - Active campaigns list
  - Trend charts (if historical data available)

#### 1.2 User Directory
```
┌─────────────────────────────────────────────────┐
│          Users Directory                        │
├─────────────────────────────────────────────────┤
│  🔍 Search: [_________________] 🔽 Filters      │
│                                                 │
│  Name              Dept        Status   Risk    │
│  ───────────────────────────────────────────────│
│  Alex Morgan       Eng         Active   🔴 High │
│  Zoe Bennett       Eng         Active   🟢 Low  │
│  Casey Diaz        Eng         Active   🟡 Med  │
│  Jules Kim         Eng         ⚠️ Left   🔴 High │
│  ...                                            │
│                                                 │
│  📄 Showing 1-50 of 374 users                   │
└─────────────────────────────────────────────────┘
```

**Implementation:**
- New route: `/users`
- API endpoint: `GET /api/users?search=&department=&status=&risk=`
- Features:
  - List all users from latest scan/campaign
  - Search by name/username
  - Filter by department, status, risk level
  - Sort by name, risk, violations
  - Pagination
  - Click user → User Details Page

#### 1.3 User Details Page
```
┌─────────────────────────────────────────────────┐
│     Alex Morgan (alex.morgan.0002)              │
├─────────────────────────────────────────────────┤
│  📋 PROFILE                                     │
│  Department: Engineering                        │
│  Role: Software Engineer                        │
│  Status: Active                                 │
│  Manager: Taylor Santos                         │
│  Start Date: 2024-03-15                         │
│                                                 │
│  🔑 ACCESS (23 entitlements)                    │
│  ✅ engineering:source-read          Expected   │
│  ✅ engineering:source-write         Expected   │
│  ⚠️ hr:employee-records-read         Violation  │
│  ✅ collaboration:workspace-read     Expected   │
│  ...                                            │
│                                                 │
│  👥 GROUP MEMBERSHIPS (5)                       │
│  • engineering_source_read                      │
│  • engineering_source_write                     │
│  • hr_employee_records_read ⚠️                  │
│  • collaboration_workspace_read                 │
│  • knowledge_articles_read                      │
│                                                 │
│  📊 RISK ASSESSMENT                             │
│  Risk Level: 🔴 High                            │
│  Violations: 1 restricted access                │
│  Last Review: 2026-09-23                        │
│                                                 │
│  📜 HISTORY                                     │
│  2026-09-23: Violation detected                 │
│  2026-06-15: Role assigned                      │
│  2024-03-15: Account created                    │
└─────────────────────────────────────────────────┘
```

**Implementation:**
- New route: `/users/:userId`
- API endpoint: `GET /api/users/:userId`
- Shows:
  - User profile from HR data
  - All access/entitlements with policy result
  - Group memberships
  - Risk score breakdown
  - Access history/changes
  - Link to any findings in campaigns

#### 1.4 Access Matrix View
```
┌─────────────────────────────────────────────────┐
│          Access Matrix                          │
├─────────────────────────────────────────────────┤
│  🔍 Filter: [Department] [Entitlement] [Risk]  │
│                                                 │
│  User              │ Finance │ HR │ Eng │ IT   │
│  ──────────────────┼─────────┼────┼─────┼──────│
│  Alex Morgan       │    ❌   │ ⚠️ │  ✅  │  ❌  │
│  Zoe Bennett       │    ❌   │ ❌ │  ✅  │  ❌  │
│  Casey Diaz        │    ❌   │ ❌ │  ✅  │  ⚠️  │
│  Jules Kim (left)  │    ❌   │ 🔴 │  🔴  │  ❌  │
│  ...                                            │
│                                                 │
│  ✅ Expected  ⚠️ Violation  🔴 Critical  ❌ None│
└─────────────────────────────────────────────────┘
```

**Implementation:**
- New route: `/access-matrix`
- API endpoint: `GET /api/access-matrix?department=&entitlement=`
- Shows:
  - Grid of users × entitlements
  - Color-coded by policy result
  - Filterable by department/entitlement
  - Interactive (click cell → details)

---

### **Phase 2: Risk & Analytics Dashboard** (2-3 weeks)
**Goal:** Continuous risk monitoring and trending.

#### 2.1 Risk Dashboard
```
┌─────────────────────────────────────────────────┐
│          Risk Dashboard                         │
├─────────────────────────────────────────────────┤
│  📊 OVERALL RISK SCORE: 7.8 / 10 🔴 HIGH        │
│                                                 │
│  ⚠️ TOP RISKS                                   │
│  1. 41 lifecycle violations (employees left)    │
│  2. 8 restricted access violations              │
│  3. 6 unlisted entitlements                     │
│  4. 12 over-privileged accounts                 │
│                                                 │
│  📈 RISK TREND (Last 90 Days)                   │
│  [Chart showing risk score over time]           │
│                                                 │
│  🎯 HIGH-RISK USERS (Risk > 8.0)                │
│  • Jules Kim (left, 5 violations)               │
│  • Casey Diaz (IT admin access)                 │
│  • Alex Morgan (restricted access)              │
│                                                 │
│  📂 RISK BY DEPARTMENT                          │
│  Engineering: 🟡 Medium (12 violations)         │
│  Finance:     🔴 High (8 violations)            │
│  HR:          🟢 Low (2 violations)             │
└─────────────────────────────────────────────────┘
```

**Implementation:**
- New route: `/risk-dashboard`
- API endpoints:
  - `GET /api/risk/summary` - Overall score, top risks
  - `GET /api/risk/trend?days=90` - Historical risk data
  - `GET /api/risk/users?threshold=8.0` - High-risk users
  - `GET /api/risk/departments` - Risk by department
- Features:
  - Calculate org-wide risk score
  - Track risk over time (requires storing snapshots)
  - Identify high-risk users
  - Department-level breakdown

---

### **Phase 3: Compliance & Reporting** (2 weeks)
**Goal:** Pre-built audit reports and compliance tracking.

#### 3.1 Compliance Dashboard
```
┌─────────────────────────────────────────────────┐
│        Compliance Dashboard                     │
├─────────────────────────────────────────────────┤
│  ✅ SOX Compliance: 92% (Target: 95%)           │
│  ✅ HIPAA Compliance: 88% (Target: 90%)         │
│  ⚠️ GDPR Compliance: 78% (Target: 95%)          │
│                                                 │
│  📋 CERTIFICATION STATUS                        │
│  Q4 Access Review: 67% complete (127 pending)   │
│  Q3 Access Review: 100% complete                │
│                                                 │
│  📊 POLICY VIOLATIONS                           │
│  Active Violations: 55                          │
│  Remediated This Quarter: 23                    │
│  Average Time to Remediate: 12 days             │
│                                                 │
│  📄 AUDIT REPORTS                               │
│  [Generate] SOX Access Report                   │
│  [Generate] HIPAA Privileged Access Report      │
│  [Generate] User Access Report (All Users)      │
│  [Generate] Violation Summary Report            │
└─────────────────────────────────────────────────┘
```

**Implementation:**
- New route: `/compliance`
- API endpoints:
  - `GET /api/compliance/status` - Compliance scores
  - `GET /api/compliance/reports` - Available reports
  - `GET /api/compliance/generate/:reportType` - Generate report
- Features:
  - Compliance KPI tracking
  - One-click report generation (PDF/CSV)
  - Audit evidence export

---

### **Phase 4: Entitlement & Role Management** (3 weeks)
**Goal:** Manage entitlements and roles as first-class objects.

#### 4.1 Entitlement Catalog
```
┌─────────────────────────────────────────────────┐
│        Entitlement Catalog                      │
├─────────────────────────────────────────────────┤
│  🔍 Search: [_________________] 🔽 Filters      │
│                                                 │
│  Entitlement                    Risk   Users    │
│  ──────────────────────────────────────────────│
│  🔴 finance:payments-approve    High     3      │
│  🔴 it:infrastructure-admin     High     2      │
│  🟡 hr:employee-records-write   Medium   5      │
│  🟢 collaboration:workspace-read Low     67     │
│  ...                                            │
│                                                 │
│  📄 Showing 1-23 of 23 entitlements             │
└─────────────────────────────────────────────────┘
```

**Implementation:**
- New route: `/entitlements`
- API endpoint: `GET /api/entitlements`
- Shows:
  - All entitlements from mapping
  - Risk classification
  - Count of users with each entitlement
  - Click entitlement → details

#### 4.2 Role Management
```
┌─────────────────────────────────────────────────┐
│        Role Management                          │
├─────────────────────────────────────────────────┤
│  Role: Software Engineer                        │
│                                                 │
│  👥 USERS WITH THIS ROLE: 12                    │
│                                                 │
│  🔑 EXPECTED ENTITLEMENTS (6)                   │
│  ✅ engineering:source-read                     │
│  ✅ engineering:source-write                    │
│  ✅ collaboration:workspace-read                │
│  ✅ collaboration:workspace-write               │
│  ✅ hr:directory-read                           │
│  ✅ knowledge:articles-read                     │
│                                                 │
│  ⚠️ COMMON VIOLATIONS                           │
│  • 2 users have hr:employee-records-read        │
│  • 1 user has finance:invoices-read             │
│                                                 │
│  📊 COMPLIANCE: 83% (10/12 users compliant)     │
└─────────────────────────────────────────────────┘
```

**Implementation:**
- New route: `/roles/:roleId`
- API endpoint: `GET /api/roles/:roleId`
- Shows:
  - Role definition from HR policies
  - Expected entitlements
  - Users with this role
  - Common violations
  - Compliance %

---

## Technical Implementation Guide

### Data Source Strategy

Your platform already has ALL the data needed. The gap is just **how you present it**.

**Current:** Data only appears in campaign findings  
**Needed:** Extract and display data independently of campaigns

### API Endpoints to Add

```typescript
// Dashboard
GET /api/dashboard/summary
Response: {
  totalUsers: 374,
  totalAssignments: 374,
  criticalFindings: 45,
  pendingDecisions: 127,
  activeCampaigns: [...],
  topRisks: [...]
}

// Users
GET /api/users?search=&department=&status=&risk=&limit=50&offset=0
GET /api/users/:userId
GET /api/users/:userId/access
GET /api/users/:userId/history

// Access Matrix
GET /api/access-matrix?users=&entitlements=
Response: [
  { userId: "...", userName: "...", entitlements: {
      "ent:finance:...": "expected",
      "ent:hr:...": "restricted"
    }
  }
]

// Risk
GET /api/risk/summary
GET /api/risk/trend?days=90
GET /api/risk/users?threshold=8.0
GET /api/risk/departments

// Entitlements
GET /api/entitlements
GET /api/entitlements/:entitlementId
GET /api/entitlements/:entitlementId/users

// Roles
GET /api/roles
GET /api/roles/:roleId
GET /api/roles/:roleId/users
```

### UI Components to Build

**Technology:** Your platform uses vanilla JavaScript (app.js). Continue with that or consider:
- **Option A:** Continue vanilla JS (lightweight, no build step)
- **Option B:** Add React/Vue (component reusability, better for complex UIs)
- **Option C:** HTMX (server-side rendering with minimal JS)

**Recommended:** Start with vanilla JS for consistency, refactor to React later if needed.

### Database Schema Additions

**Current:** SQLite with campaigns, findings, decisions, audit events

**Add:**
```sql
-- Store historical snapshots for trending
CREATE TABLE risk_snapshots (
  id INTEGER PRIMARY KEY,
  snapshot_date TEXT NOT NULL,
  total_users INTEGER,
  total_violations INTEGER,
  risk_score REAL,
  critical_count INTEGER,
  high_count INTEGER,
  medium_count INTEGER,
  low_count INTEGER,
  data_json TEXT -- Full snapshot for detailed analysis
);

-- Track user access history
CREATE TABLE access_history (
  id INTEGER PRIMARY KEY,
  user_id TEXT NOT NULL,
  entitlement_id TEXT NOT NULL,
  action TEXT NOT NULL, -- granted, revoked, certified
  timestamp TEXT NOT NULL,
  campaign_id TEXT,
  actor_id TEXT,
  reason TEXT
);
```

---

## Quick Wins (Can Implement Today)

### 1. **Simple Identity Dashboard** (4 hours)

Add a new route to `api.py`:

```python
@app.get("/api/dashboard/summary")
async def dashboard_summary(actor: User = Depends(authenticate)):
    # Get latest campaign
    latest_campaign = service.list_campaigns(actor)['campaigns'][0]
    campaign = service.get_campaign(latest_campaign['id'], actor)
    
    # Calculate summary
    findings = campaign['findings']
    return {
        'totalUsers': len(set(f['account_id'] for f in findings)),
        'totalAssignments': len([f for f in findings if f['kind'] == 'assignment']),
        'criticalFindings': len([f for f in findings if f['risk_level'] == 'critical']),
        'pendingDecisions': len([f for f in findings if f['status'] == 'pending']),
        'violationBreakdown': {
            'lifecycle_restricted': len([f for f in findings if f['policy_result'] == 'lifecycle_restricted']),
            'restricted': len([f for f in findings if f['policy_result'] == 'restricted']),
            'unlisted': len([f for f in findings if f['policy_result'] == 'unlisted'])
        }
    }
```

Add dashboard HTML to `static/app.js`:

```javascript
async function renderDashboard() {
    const data = await api.get('/api/dashboard/summary');
    
    document.getElementById('dashboard-content').innerHTML = `
        <h1>Dashboard</h1>
        
        <div class="summary-cards">
            <div class="card">
                <div class="value">${data.totalUsers}</div>
                <div class="label">Users</div>
            </div>
            <div class="card">
                <div class="value">${data.totalAssignments}</div>
                <div class="label">Access Assignments</div>
            </div>
            <div class="card critical">
                <div class="value">${data.criticalFindings}</div>
                <div class="label">Critical Findings</div>
            </div>
            <div class="card">
                <div class="value">${data.pendingDecisions}</div>
                <div class="label">Pending Decisions</div>
            </div>
        </div>
        
        <div class="violations">
            <h2>Top Risks</h2>
            <ul>
                <li>${data.violationBreakdown.lifecycle_restricted} lifecycle violations (employees left)</li>
                <li>${data.violationBreakdown.restricted} restricted access violations</li>
                <li>${data.violationBreakdown.unlisted} unlisted entitlements</li>
            </ul>
        </div>
    `;
}
```

### 2. **User Directory** (4 hours)

```python
@app.get("/api/users")
async def list_users(
    search: str = "",
    department: str = "",
    status: str = "",
    limit: int = 50,
    offset: int = 0,
    actor: User = Depends(authenticate)
):
    # Get latest campaign
    latest_campaign = service.list_campaigns(actor)['campaigns'][0]
    campaign = service.get_campaign(latest_campaign['id'], actor)
    
    # Extract unique users from findings
    users_map = {}
    for finding in campaign['findings']:
        if finding['account_id'] not in users_map:
            users_map[finding['account_id']] = {
                'userId': finding['account_id'],
                'username': finding['username'],
                'fullName': finding['full_name'],
                'department': finding['department'],
                'role': finding['role_name'],
                'employmentStatus': finding['employment_status'],
                'riskLevel': 'low',
                'violationCount': 0
            }
        
        # Update risk/violations
        if finding['policy_result'] in ['lifecycle_restricted', 'restricted', 'unlisted']:
            users_map[finding['account_id']]['violationCount'] += 1
            if finding['risk_level'] in ['critical', 'high']:
                users_map[finding['account_id']]['riskLevel'] = finding['risk_level']
    
    users = list(users_map.values())
    
    # Filter
    if search:
        users = [u for u in users if search.lower() in u['fullName'].lower() or search.lower() in u['username'].lower()]
    if department:
        users = [u for u in users if u['department'] == department]
    if status:
        users = [u for u in users if u['employmentStatus'] == status]
    
    return {
        'users': users[offset:offset+limit],
        'total': len(users)
    }
```

---

## Summary & Next Steps

**You have a strong foundation:**
- ✅ Access review campaigns (core IGA functionality)
- ✅ Policy evaluation engine
- ✅ Remediation workflow
- ✅ Audit trail
- ✅ AI-assisted reviews

**What's missing:**
- ❌ A unified person-centric directory/access graph across sources (basic environment/account visibility already exists)
- ❌ Continuous risk monitoring
- ❌ Compliance dashboards
- ❌ Lifecycle automation

**Recommended Priority:**
0. **Immediate prerequisite:** Validate and operate the Environment → fresh scan → durable campaign → human review workflow before expanding dashboards.
1. **Phase 1:** Identity Dashboard + User Directory (HIGH IMPACT, 3-4 weeks)
2. **Phase 2:** Risk Dashboard (HIGH VALUE, 2-3 weeks)
3. **Phase 3:** Compliance Reporting (AUDIT READY, 2 weeks)
4. **Phase 4:** Entitlement/Role Management (NICE TO HAVE, 3 weeks)

**Quick Wins (This Week):**
- Complete environment-first acceptance and document server-managed source inputs
- Validate live Linux discovery/recovery on an authorized target
- Evaluate an explicitly approved external AI provider and its fallback behavior
- Then consider `/api/dashboard/summary` and a person-centric directory

This will immediately make your platform feel more like a "complete IGA solution" instead of just a "campaign review tool."

---

Broader identity dashboards follow the environment-first acceptance work.
