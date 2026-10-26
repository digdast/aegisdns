/**
 * AegisDNS - Executive Cyber Security Command Center JavaScript SPA
 * Handles real-time WebSockets, dynamic telemetry charts, 1-click allow/block,
 * domain threat auditor, and comprehensive DNS configuration.
 */

class AegisApp {
    constructor() {
        this.activeTab = 'dashboard';
        this.ws = null;
        this.chart = null;
        this.queryFilter = 'ALL';
        this.searchDebounce = null;
        this.stats = null;

        this.initEventListeners();
        this.initWebSocket();
        this.loadDashboardData();
        
        // Periodic background poll every 15s to keep stats fresh
        setInterval(() => this.loadStatsOnly(), 15000);
    }

    initEventListeners() {
        // Tab Navigation
        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                const targetTab = item.dataset.tab;
                this.switchTab(targetTab);
            });
        });

        // Query Log Filter Buttons
        document.querySelectorAll('.btn-filter').forEach(btn => {
            btn.addEventListener('click', () => {
                document.querySelectorAll('.btn-filter').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                this.queryFilter = btn.dataset.filter;
                this.loadQueries();
            });
        });

        // Search Input
        const searchInput = document.getElementById('querySearchInput');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                clearTimeout(this.searchDebounce);
                this.searchDebounce = setTimeout(() => {
                    this.loadQueries();
                }, 300);
            });
        }

        // Domain Auditor Form
        const auditForm = document.getElementById('auditForm');
        if (auditForm) {
            auditForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.runDomainAudit();
            });
        }

        // Add Rule Form
        const ruleForm = document.getElementById('addRuleForm');
        if (ruleForm) {
            ruleForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.submitCustomRule();
            });
        }

        // Add Local DNS Form
        const localDnsForm = document.getElementById('addLocalDnsForm');
        if (localDnsForm) {
            localDnsForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.submitLocalDnsRecord();
            });
        }

        // Add Blocklist Form
        const blocklistForm = document.getElementById('addBlocklistForm');
        if (blocklistForm) {
            blocklistForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.submitBlocklistFeed();
            });
        }

        // Update Feeds Button
        const updateFeedsBtn = document.getElementById('btnUpdateFeeds');
        if (updateFeedsBtn) {
            updateFeedsBtn.addEventListener('click', () => this.updateBlocklists());
        }

        // Settings Form
        const settingsForm = document.getElementById('settingsForm');
        if (settingsForm) {
            settingsForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.saveSettings();
            });
        }
    }

    switchTab(tabId) {
        this.activeTab = tabId;
        
        // Update nav items
        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.toggle('active', item.dataset.tab === tabId);
        });

        // Update viewports
        document.querySelectorAll('.tab-pane').forEach(pane => {
            pane.classList.remove('active');
        });
        const targetPane = document.getElementById(`tab-${tabId}`);
        if (targetPane) targetPane.classList.add('active');

        // Update page title
        const titles = {
            dashboard: 'Executive Telemetry & Threat Dashboard',
            queries: 'Live Query Stream & Defense Feed',
            auditor: 'Domain Threat Intelligence & DNS Inspector',
            blocklists: 'Threat Feeds & Adware Sinkhole Sources',
            rules: 'Custom Rules & White/Blacklists',
            localdns: 'Local DNS & Homelab Rewrites',
            settings: 'Resolver Engine & DNS Settings'
        };
        const titleEl = document.getElementById('pageTitle');
        if (titleEl) titleEl.innerText = titles[tabId] || 'Command Center';

        // Lazy load tab data
        if (tabId === 'queries') this.loadQueries();
        if (tabId === 'blocklists') this.loadBlocklists();
        if (tabId === 'rules') this.loadRules();
        if (tabId === 'localdns') this.loadLocalDns();
        if (tabId === 'settings') this.loadSettings();
    }

    // -------------------------------------------------------------
    // WebSocket Real-time Feed
    // -------------------------------------------------------------

    initWebSocket() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws/live`;
        
        try {
            this.ws = new WebSocket(wsUrl);

            this.ws.onopen = () => {
                const wsBadge = document.getElementById('wsStatusBadge');
                if (wsBadge) {
                    wsBadge.innerHTML = '<span class="pulse-dot"></span> Live Stream Active';
                    wsBadge.style.color = 'var(--emerald-safe)';
                }
            };

            this.ws.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    this.handleLiveQuery(data);
                } catch (e) {
                    console.error('WS Parse error', e);
                }
            };

            this.ws.onclose = () => {
                const wsBadge = document.getElementById('wsStatusBadge');
                if (wsBadge) {
                    wsBadge.innerText = 'Stream Disconnected (Reconnecting...)';
                    wsBadge.style.color = 'var(--amber-warning)';
                }
                setTimeout(() => this.initWebSocket(), 3000);
            };

            this.ws.onerror = () => {
                if (this.ws) this.ws.close();
            };
        } catch (e) {
            console.error('WS Init error', e);
        }
    }

    handleLiveQuery(meta) {
        // Increment KPI counters
        const totalEl = document.getElementById('kpiTotalQueries');
        if (totalEl) {
            const cur = parseInt(totalEl.innerText.replace(/,/g, '')) || 0;
            totalEl.innerText = (cur + 1).toLocaleString();
        }

        if (meta.status.startsWith('BLOCKED')) {
            const blockedEl = document.getElementById('kpiBlockedQueries');
            if (blockedEl) {
                const cur = parseInt(blockedEl.innerText.replace(/,/g, '')) || 0;
                blockedEl.innerText = (cur + 1).toLocaleString();
            }
        }

        // If queries tab is active, prepend row to table
        if (this.activeTab === 'queries') {
            const tbody = document.getElementById('queriesTableBody');
            if (tbody) {
                const row = this.renderQueryRow(meta);
                tbody.insertAdjacentHTML('afterbegin', row);
                // Keep max 100 rows in DOM
                if (tbody.children.length > 100) {
                    tbody.removeChild(tbody.lastChild);
                }
            }
        }
    }

    // -------------------------------------------------------------
    // Dashboard Data & Charts
    // -------------------------------------------------------------

    async loadDashboardData() {
        try {
            const res = await fetch('/api/stats');
            const data = await res.json();
            this.stats = data;
            this.renderKPIs(data);
            this.renderTimelineChart(data.timeline || []);
            this.renderTopLists(data);
        } catch (e) {
            console.error('Failed to load dashboard stats', e);
        }
    }

    async loadStatsOnly() {
        try {
            const res = await fetch('/api/stats');
            const data = await res.json();
            this.stats = data;
            this.renderKPIs(data);
        } catch (e) {}
    }

    renderKPIs(data) {
        document.getElementById('kpiTotalQueries').innerText = (data.total_queries || 0).toLocaleString();
        document.getElementById('kpiBlockedQueries').innerText = (data.blocked_queries || 0).toLocaleString();
        document.getElementById('kpiBlockRatio').innerText = `${data.block_ratio || 0}%`;
        document.getElementById('kpiMalwareBlocked').innerText = (data.malware_blocked || 0).toLocaleString();
        document.getElementById('kpiCacheRatio').innerText = `${data.cache_ratio || 0}%`;
        document.getElementById('kpiAvgLatency').innerText = `${data.avg_latency_ms || 0} ms`;
        document.getElementById('kpiActiveClients').innerText = data.active_clients || 1;
        document.getElementById('kpiTotalRules').innerText = (data.total_rules_active || 0).toLocaleString();

        const modeBadge = document.getElementById('engineModeBadge');
        if (modeBadge && data.active_mode) {
            modeBadge.innerText = `ENGINE: ${data.active_mode}`;
        }
    }

    renderTimelineChart(timeline) {
        const ctx = document.getElementById('queryTimelineChart');
        if (!ctx) return;

        const labels = timeline.map(t => t.hour.split(' ')[1] || t.hour);
        const allowedData = timeline.map(t => t.allowed);
        const blockedData = timeline.map(t => t.blocked);

        if (this.chart) {
            this.chart.destroy();
        }

        this.chart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: labels.length ? labels : ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'],
                datasets: [
                    {
                        label: 'Allowed Queries',
                        data: allowedData.length ? allowedData : [0, 0, 0, 0, 0, 0],
                        borderColor: '#06b6d4',
                        backgroundColor: 'rgba(6, 182, 212, 0.1)',
                        fill: true,
                        tension: 0.35,
                        borderWidth: 2,
                        pointRadius: 3,
                        pointBackgroundColor: '#06b6d4'
                    },
                    {
                        label: 'Blocked Threat/Ads',
                        data: blockedData.length ? blockedData : [0, 0, 0, 0, 0, 0],
                        borderColor: '#f43f5e',
                        backgroundColor: 'rgba(244, 63, 94, 0.15)',
                        fill: true,
                        tension: 0.35,
                        borderWidth: 2,
                        pointRadius: 3,
                        pointBackgroundColor: '#f43f5e'
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'top',
                        labels: {
                            color: '#94a3b8',
                            font: { family: 'Outfit', size: 12, weight: '500' }
                        }
                    },
                    tooltip: {
                        backgroundColor: 'rgba(15, 23, 42, 0.9)',
                        titleColor: '#f8fafc',
                        bodyColor: '#cbd5e1',
                        borderColor: 'rgba(6, 182, 212, 0.3)',
                        borderWidth: 1
                    }
                },
                scales: {
                    x: {
                        grid: { color: 'rgba(255, 255, 255, 0.04)' },
                        ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 } }
                    },
                    y: {
                        grid: { color: 'rgba(255, 255, 255, 0.04)' },
                        ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 } },
                        beginAtZero: true
                    }
                }
            }
        });
    }

    renderTopLists(data) {
        // Top Blocked Domains
        const blockedContainer = document.getElementById('topBlockedList');
        if (blockedContainer) {
            if (!data.top_blocked || data.top_blocked.length === 0) {
                blockedContainer.innerHTML = '<div class="top-list-item" style="color: var(--text-muted);">No blocked queries recorded yet.</div>';
            } else {
                blockedContainer.innerHTML = data.top_blocked.map(item => `
                    <div class="top-list-item">
                        <span class="top-list-domain" title="${item.domain}">${item.domain}</span>
                        <span class="top-list-count blocked">${item.count.toLocaleString()}</span>
                    </div>
                `).join('');
            }
        }

        // Top Allowed Domains
        const allowedContainer = document.getElementById('topAllowedList');
        if (allowedContainer) {
            if (!data.top_allowed || data.top_allowed.length === 0) {
                allowedContainer.innerHTML = '<div class="top-list-item" style="color: var(--text-muted);">No allowed queries recorded yet.</div>';
            } else {
                allowedContainer.innerHTML = data.top_allowed.map(item => `
                    <div class="top-list-item">
                        <span class="top-list-domain" title="${item.domain}">${item.domain}</span>
                        <span class="top-list-count">${item.count.toLocaleString()}</span>
                    </div>
                `).join('');
            }
        }

        // Top Clients
        const clientContainer = document.getElementById('topClientsList');
        if (clientContainer) {
            if (!data.top_clients || data.top_clients.length === 0) {
                clientContainer.innerHTML = '<div class="top-list-item" style="color: var(--text-muted);">No client traffic yet.</div>';
            } else {
                clientContainer.innerHTML = data.top_clients.map(item => `
                    <div class="top-list-item">
                        <span class="top-list-domain">${item.client_ip}</span>
                        <span class="top-list-count">${item.count.toLocaleString()} queries</span>
                    </div>
                `).join('');
            }
        }
    }

    // -------------------------------------------------------------
    // Live Query Log Tab
    // -------------------------------------------------------------

    async loadQueries() {
        const tbody = document.getElementById('queriesTableBody');
        if (!tbody) return;

        const searchVal = document.getElementById('querySearchInput')?.value || '';
        let url = `/api/queries?limit=100&status=${this.queryFilter}`;
        if (searchVal) url += `&search=${encodeURIComponent(searchVal)}`;

        try {
            const res = await fetch(url);
            const queries = await res.json();
            if (queries.length === 0) {
                tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; padding: 24px; color: var(--text-muted);">No queries match your criteria.</td></tr>';
                return;
            }
            tbody.innerHTML = queries.map(q => this.renderQueryRow(q)).join('');
        } catch (e) {
            console.error('Failed to load queries', e);
        }
    }

    renderQueryRow(q) {
        const d = new Date(q.timestamp * 1000);
        const timeStr = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        
        let statusClass = 'allowed';
        let statusLabel = 'ALLOWED';
        if (q.status === 'BLOCKED_AD') {
            statusClass = 'blocked-ad';
            statusLabel = 'BLOCKED (AD)';
        } else if (q.status === 'BLOCKED_MALWARE') {
            statusClass = 'blocked-malware';
            statusLabel = 'BLOCKED (THREAT)';
        } else if (q.status === 'CACHED') {
            statusClass = 'cached';
            statusLabel = 'CACHED';
        } else if (q.status === 'REWRITE') {
            statusClass = 'rewrite';
            statusLabel = 'LOCAL REWRITE';
        }

        const isBlocked = q.status.startsWith('BLOCKED');
        const actionBtn = isBlocked
            ? `<button class="btn-action allow" onclick="app.quickAction('${q.domain}', 'ALLOW')">Quick Whitelist</button>`
            : `<button class="btn-action block" onclick="app.quickAction('${q.domain}', 'BLOCK_AD')">Quick Block</button>`;

        return `
            <tr>
                <td style="font-family: var(--font-mono); color: var(--text-muted); font-size: 0.8rem;">${timeStr}</td>
                <td style="font-family: var(--font-mono); color: var(--text-secondary);">${q.client_ip}</td>
                <td style="font-family: var(--font-mono); font-weight: 600; color: #ffffff;">${q.domain}</td>
                <td><span style="font-family: var(--font-mono); font-size: 0.75rem; background: rgba(255,255,255,0.06); padding: 2px 6px; border-radius: 4px;">${q.query_type}</span></td>
                <td><span class="status-badge ${statusClass}">${statusLabel}</span></td>
                <td style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--cyan-primary);">${q.latency_ms} ms</td>
                <td>${actionBtn}</td>
            </tr>
        `;
    }

    async quickAction(domain, action) {
        try {
            const res = await fetch('/api/quick-action', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ domain, action })
            });
            if (res.ok) {
                this.showToast(action === 'ALLOW' ? `Whitelisted ${domain}` : `Blocked ${domain}`, 'success');
                this.loadQueries();
                this.loadStatsOnly();
            }
        } catch (e) {
            this.showToast(`Action failed: ${e}`, 'error');
        }
    }

    // -------------------------------------------------------------
    // Domain Threat Auditor
    // -------------------------------------------------------------

    async runDomainAudit() {
        const input = document.getElementById('auditDomainInput');
        if (!input || !input.value.trim()) return;

        const domain = input.value.trim();
        const card = document.getElementById('auditResultCard');
        card.classList.remove('active');

        try {
            const res = await fetch('/api/audit-domain', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ domain })
            });
            const data = await res.json();

            document.getElementById('auditResultDomain').innerText = data.domain;
            
            const badge = document.getElementById('auditResultVerdict');
            if (data.filter_status === 'ALLOWED') {
                badge.className = 'status-badge allowed';
                badge.innerText = 'ALLOWED / CLEAN';
            } else if (data.filter_status === 'BLOCKED_AD') {
                badge.className = 'status-badge blocked-ad';
                badge.innerText = 'AD / TRACKER DETECTED';
            } else if (data.filter_status === 'BLOCKED_MALWARE') {
                badge.className = 'status-badge blocked-malware';
                badge.innerText = 'MALWARE / THREAT BLOCKED';
            } else if (data.filter_status === 'SAFESEARCH') {
                badge.className = 'status-badge rewrite';
                badge.innerText = 'SAFESEARCH ENFORCED';
            }

            document.getElementById('auditResultReason').innerText = data.block_reason || 'Passed all security heuristics';
            document.getElementById('auditResultUpstream').innerText = data.upstream_used || 'Local Sinkhole';
            document.getElementById('auditResultLatency').innerText = `${data.latency_ms} ms`;
            document.getElementById('auditResultRCode').innerText = data.rcode || 'NOERROR';

            const recordsEl = document.getElementById('auditResultRecords');
            if (data.resolved_answers && data.resolved_answers.length > 0) {
                recordsEl.innerHTML = data.resolved_answers.map(a => `
                    <div style="font-family: var(--font-mono); font-size: 0.85rem; color: #a5f3fc; padding: 4px 0;">
                        [${a.type}] ${a.data} (TTL ${a.ttl}s)
                    </div>
                `).join('');
            } else {
                recordsEl.innerHTML = '<span style="color: var(--text-muted); font-size: 0.85rem;">No answers returned.</span>';
            }

            card.classList.add('active');
        } catch (e) {
            this.showToast(`Audit failed: ${e}`, 'error');
        }
    }

    // -------------------------------------------------------------
    // Blocklists & Feeds
    // -------------------------------------------------------------

    async loadBlocklists() {
        const container = document.getElementById('blocklistsContainer');
        if (!container) return;

        try {
            const res = await fetch('/api/blocklists');
            const lists = await res.json();

            container.innerHTML = lists.map(b => `
                <div class="glass-panel" style="margin-bottom: 16px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                        <div>
                            <span style="font-weight: 700; font-size: 1.05rem; color: #ffffff;">${b.name}</span>
                            <span class="brand-badge" style="margin-left: 8px;">${b.category}</span>
                        </div>
                        <label class="switch">
                            <input type="checkbox" ${b.enabled ? 'checked' : ''} onchange="app.toggleBlocklist(${b.id}, this.checked)">
                            <span class="slider"></span>
                        </label>
                    </div>
                    <div style="font-size: 0.85rem; color: var(--text-secondary); margin-bottom: 10px;">${b.description || ''}</div>
                    <div style="font-family: var(--font-mono); font-size: 0.78rem; color: var(--text-muted); margin-bottom: 12px; word-break: break-all;">${b.url}</div>
                    <div style="display: flex; justify-content: space-between; align-items: center; border-top: 1px solid var(--border-subtle); padding-top: 10px; font-size: 0.82rem;">
                        <span style="color: var(--cyan-primary); font-family: var(--font-mono); font-weight: 600;">${b.domain_count ? b.domain_count.toLocaleString() : 0} rules active</span>
                        <span style="color: var(--text-muted);">Updated: ${b.last_updated || 'Never'}</span>
                    </div>
                </div>
            `).join('');
        } catch (e) {
            console.error('Failed to load blocklists', e);
        }
    }

    async toggleBlocklist(id, enabled) {
        try {
            await fetch(`/api/blocklists/toggle/${id}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ enabled })
            });
            this.showToast('Blocklist rule updated', 'success');
        } catch (e) {
            this.showToast('Error updating feed', 'error');
        }
    }

    async updateBlocklists() {
        const btn = document.getElementById('btnUpdateFeeds');
        if (btn) {
            btn.disabled = true;
            btn.innerHTML = 'Updating Feeds...';
        }

        try {
            const res = await fetch('/api/blocklists/update', { method: 'POST' });
            const data = await res.json();
            this.showToast(`Updated! Active rules: ${(data.active_ads + data.active_malware).toLocaleString()}`, 'success');
            this.loadBlocklists();
            this.loadStatsOnly();
        } catch (e) {
            this.showToast('Failed to update feeds', 'error');
        } finally {
            if (btn) {
                btn.disabled = false;
                btn.innerHTML = 'Update All Feeds Now';
            }
        }
    }

    async submitBlocklistFeed() {
        const name = document.getElementById('newFeedName').value.trim();
        const url = document.getElementById('newFeedUrl').value.trim();
        const category = document.getElementById('newFeedCategory').value;
        const description = document.getElementById('newFeedDesc').value.trim();

        if (!name || !url) return;

        try {
            const res = await fetch('/api/blocklists', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name, url, category, description })
            });
            if (res.ok) {
                this.showToast('Threat feed added successfully', 'success');
                document.getElementById('addBlocklistForm').reset();
                this.loadBlocklists();
            }
        } catch (e) {
            this.showToast(`Error adding feed: ${e}`, 'error');
        }
    }

    // -------------------------------------------------------------
    // Custom Rules Tab
    // -------------------------------------------------------------

    async loadRules() {
        const tbody = document.getElementById('rulesTableBody');
        if (!tbody) return;

        try {
            const res = await fetch('/api/rules');
            const rules = await res.json();
            if (rules.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; padding: 20px; color: var(--text-muted);">No custom rules defined yet.</td></tr>';
                return;
            }
            tbody.innerHTML = rules.map(r => `
                <tr>
                    <td style="font-family: var(--font-mono); font-weight: 600; color: #ffffff;">${r.domain}</td>
                    <td><span class="status-badge ${r.rule_type === 'ALLOW' ? 'allowed' : 'blocked-malware'}">${r.rule_type}</span></td>
                    <td style="color: var(--text-secondary); font-size: 0.85rem;">${r.comment || ''}</td>
                    <td style="font-family: var(--font-mono); font-size: 0.78rem; color: var(--text-muted);">${r.created_at}</td>
                    <td><button class="btn-danger" style="padding: 4px 10px; font-size: 0.75rem;" onclick="app.deleteRule(${r.id})">Delete</button></td>
                </tr>
            `).join('');
        } catch (e) {
            console.error('Failed to load rules', e);
        }
    }

    async submitCustomRule() {
        const domain = document.getElementById('newRuleDomain').value.trim();
        const rule_type = document.getElementById('newRuleType').value;
        const comment = document.getElementById('newRuleComment').value.trim();

        if (!domain) return;

        try {
            const res = await fetch('/api/rules', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ domain, rule_type, comment })
            });
            if (res.ok) {
                this.showToast(`Rule added for ${domain}`, 'success');
                document.getElementById('addRuleForm').reset();
                this.loadRules();
            }
        } catch (e) {
            this.showToast('Error adding rule', 'error');
        }
    }

    async deleteRule(id) {
        try {
            await fetch(`/api/rules/${id}`, { method: 'DELETE' });
            this.showToast('Rule deleted', 'success');
            this.loadRules();
        } catch (e) {
            this.showToast('Failed to delete rule', 'error');
        }
    }

    // -------------------------------------------------------------
    // Local DNS Records
    // -------------------------------------------------------------

    async loadLocalDns() {
        const tbody = document.getElementById('localDnsTableBody');
        if (!tbody) return;

        try {
            const res = await fetch('/api/local-dns');
            const records = await res.json();
            if (records.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding: 20px; color: var(--text-muted);">No local records configured.</td></tr>';
                return;
            }
            tbody.innerHTML = records.map(r => `
                <tr>
                    <td style="font-family: var(--font-mono); font-weight: 600; color: #ffffff;">${r.domain}</td>
                    <td><span class="brand-badge">${r.record_type}</span></td>
                    <td style="font-family: var(--font-mono); color: var(--cyan-primary);">${r.value}</td>
                    <td style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--text-muted);">${r.ttl}s</td>
                    <td style="color: var(--text-secondary); font-size: 0.85rem;">${r.comment || ''}</td>
                    <td><button class="btn-danger" style="padding: 4px 10px; font-size: 0.75rem;" onclick="app.deleteLocalDns(${r.id})">Delete</button></td>
                </tr>
            `).join('');
        } catch (e) {
            console.error('Failed to load local DNS', e);
        }
    }

    async submitLocalDnsRecord() {
        const domain = document.getElementById('newDnsDomain').value.trim();
        const record_type = document.getElementById('newDnsType').value;
        const value = document.getElementById('newDnsValue').value.trim();
        const ttl = parseInt(document.getElementById('newDnsTtl').value) || 300;
        const comment = document.getElementById('newDnsComment').value.trim();

        if (!domain || !value) return;

        try {
            const res = await fetch('/api/local-dns', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ domain, record_type, value, ttl, comment })
            });
            if (res.ok) {
                this.showToast(`Created DNS record for ${domain}`, 'success');
                document.getElementById('addLocalDnsForm').reset();
                this.loadLocalDns();
            }
        } catch (e) {
            this.showToast('Failed to create DNS record', 'error');
        }
    }

    async deleteLocalDns(id) {
        try {
            await fetch(`/api/local-dns/${id}`, { method: 'DELETE' });
            this.showToast('Record deleted', 'success');
            this.loadLocalDns();
        } catch (e) {
            this.showToast('Failed to delete record', 'error');
        }
    }

    // -------------------------------------------------------------
    // Settings Tab
    // -------------------------------------------------------------

    async loadSettings() {
        try {
            const res = await fetch('/api/settings');
            const data = await res.json();

            const modeRadio = document.querySelector(`input[name="resMode"][value="${data.resolution_mode || 'RECURSIVE'}"]`);
            if (modeRadio) modeRadio.checked = true;

            const safesearchToggle = document.getElementById('safesearchToggle');
            if (safesearchToggle) {
                safesearchToggle.checked = (data.safesearch_enabled || 'true') === 'true';
            }

            const blockModeSelect = document.getElementById('blockingModeSelect');
            if (blockModeSelect) {
                blockModeSelect.value = data.blocking_mode || 'ZERO_IP';
            }

            const upstreamDohInput = document.getElementById('upstreamDohInput');
            if (upstreamDohInput) {
                upstreamDohInput.value = data.upstream_doh || 'https://dns.quad9.net/dns-query';
            }

            const unboundAddrInput = document.getElementById('unboundAddrInput');
            if (unboundAddrInput) {
                unboundAddrInput.value = data.unbound_addr || '127.0.0.1:5335';
            }
        } catch (e) {
            console.error('Failed to load settings', e);
        }
    }

    async saveSettings() {
        const modeRadio = document.querySelector('input[name="resMode"]:checked');
        const resolution_mode = modeRadio ? modeRadio.value : 'RECURSIVE';
        const safesearch_enabled = document.getElementById('safesearchToggle').checked ? 'true' : 'false';
        const blocking_mode = document.getElementById('blockingModeSelect').value;
        const upstream_doh = document.getElementById('upstreamDohInput').value.trim();
        const unbound_addr = document.getElementById('unboundAddrInput').value.trim();

        try {
            const res = await fetch('/api/settings', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    resolution_mode,
                    safesearch_enabled,
                    blocking_mode,
                    upstream_doh,
                    unbound_addr
                })
            });
            if (res.ok) {
                this.showToast('Settings saved successfully', 'success');
                this.loadDashboardData();
            }
        } catch (e) {
            this.showToast('Failed to save settings', 'error');
        }
    }

    // -------------------------------------------------------------
    // Toast Notifications
    // -------------------------------------------------------------

    showToast(message, type = 'info') {
        const container = document.getElementById('toastContainer');
        if (!container) return;

        const toast = document.createElement('div');
        toast.className = 'toast';
        toast.innerHTML = `
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="${type === 'success' ? 'var(--emerald-safe)' : 'var(--rose-danger)'}" stroke-width="2">
                <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
                <polyline points="22 4 12 14.01 9 11.01"></polyline>
            </svg>
            <span>${message}</span>
        `;
        container.appendChild(toast);

        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateY(10px)';
            toast.style.transition = 'all 0.3s ease';
            setTimeout(() => toast.remove(), 300);
        }, 3500);
    }
}

// Global instance
window.app = new AegisApp();
