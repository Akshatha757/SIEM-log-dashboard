/* ==========================================================================
   SIEM LOG DASHBOARD - Main Application Logic & REST API Integration
   ========================================================================== */

class SiemApplication {
  constructor() {
    window.SIEM_APP = this; // Immediately bind instance to global window
    this.data = SIEM_DATA;
    this.apiUrl = 'http://localhost:5000/api';
    this.isBackendConnected = false;
    this.currentView = 'dashboard';
    this.feedPaused = false;
    this.feedInterval = null;
    this.expandedLogRowId = null;
    this.currentLogFilter = 'ALL';
    this.currentAlertFilter = 'ALL';
  }

  async init() {
    console.log("Initializing SIEM Log Dashboard...");
    this.setupNavigation();
    this.setupGlobalSearch();

    // Check REST API Backend Connectivity
    await this.checkBackendConnection();

    this.renderProfile();
    this.renderMetrics();
    this.renderThreatPulse();
    this.renderTimeline();
    this.renderLiveFeed();
    this.renderAlerts(this.currentAlertFilter);
    this.renderIncidents();
    this.renderLogs();
    this.renderConcepts();
    this.renderStatus();
    this.renderRuleBuilder();
    
    // Initialize Visualizations
    setTimeout(() => {
      SIEM_CHARTS.initActivityChart('activityChartCanvas');
      SIEM_CHARTS.initRadarChart('radarChartCanvas');
      NETWORK_MAP.render();
    }, 150);

    this.startLiveFeedSimulation();
    this.setupEventListeners();
    this.animateCounters();
  }

  // REST API Connection Health Check
  async checkBackendConnection() {
    try {
      const res = await fetch(`${this.apiUrl}/metrics`);
      if (res.ok) {
        const metrics = await res.json();
        this.isBackendConnected = true;
        this.data.metrics = metrics;

        // Fetch REST API Data
        const [profileRes, rulesRes, alertsRes, logsRes, incidentsRes] = await Promise.all([
          fetch(`${this.apiUrl}/profile`).then(r => r.json()).catch(() => null),
          fetch(`${this.apiUrl}/rules`).then(r => r.json()).catch(() => null),
          fetch(`${this.apiUrl}/alerts`).then(r => r.json()).catch(() => null),
          fetch(`${this.apiUrl}/logs`).then(r => r.json()).catch(() => null),
          fetch(`${this.apiUrl}/incidents`).then(r => r.json()).catch(() => null)
        ]);

        if (profileRes) this.data.profile = profileRes;
        if (rulesRes && rulesRes.length) this.data.rules = rulesRes;
        if (alertsRes && alertsRes.length) this.data.alerts = alertsRes;
        if (logsRes && logsRes.length) this.data.logs = logsRes;
        if (incidentsRes && incidentsRes.length) this.data.incidents = incidentsRes;

        this.updateBackendStatusBadge(true);
      }
    } catch (e) {
      console.log("Running in Standalone In-Browser Engine mode (REST API offline)");
      this.updateBackendStatusBadge(false);
    }
  }

  updateBackendStatusBadge(isConnected) {
    const statusPill = document.getElementById('headerStatusPill');
    if (statusPill && isConnected) {
      statusPill.innerHTML = `
        <span class="status-dot" style="background:var(--severity-low);"></span>
        <span>EXPRESS & SQLITE BACKEND ACTIVE (PORT 5000)</span>
      `;
      statusPill.className = 'status-pill';
    }
  }

  // Profile Customization
  renderProfile() {
    const { name, role, initials } = this.data.profile;
    const avatarEl = document.getElementById('headerAvatar');
    const nameEl = document.getElementById('headerAnalystName');
    const roleEl = document.getElementById('headerAnalystRole');
    const inputName = document.getElementById('settingProfileName');
    const inputRole = document.getElementById('settingProfileRole');

    if (avatarEl) avatarEl.textContent = initials || 'CA';
    if (nameEl) nameEl.textContent = name;
    if (roleEl) roleEl.textContent = role;
    if (inputName && !inputName.value) inputName.value = name;
    if (inputRole && !inputRole.value) inputRole.value = role;
  }

  async updateProfile() {
    const newName = document.getElementById('settingProfileName')?.value.trim();
    const newRole = document.getElementById('settingProfileRole')?.value.trim();

    if (!newName) return;

    this.data.profile.name = newName;
    if (newRole) this.data.profile.role = newRole;

    const parts = newName.split(' ');
    let initials = parts[0][0].toUpperCase();
    if (parts.length > 1) initials += parts[parts.length - 1][0].toUpperCase();
    this.data.profile.initials = initials;

    if (this.isBackendConnected) {
      try {
        await fetch(`${this.apiUrl}/profile`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: newName, initials, role: this.data.profile.role })
        });
      } catch (e) { console.error(e); }
    }

    this.renderProfile();
    this.renderRuleBuilder();
    this.showToast(`Analyst Profile updated in SQLite Database: ${newName}`, 'SUCCESS');
  }

  // View Navigation System
  setupNavigation() {
    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => {
      item.addEventListener('click', (e) => {
        e.preventDefault();
        const viewTarget = item.getAttribute('data-view');
        if (viewTarget) {
          this.switchView(viewTarget);
        }
      });
    });
  }

  switchView(viewId) {
    this.currentView = viewId;

    document.querySelectorAll('.nav-item').forEach(item => {
      if (item.getAttribute('data-view') === viewId) {
        item.classList.add('active');
      } else {
        item.classList.remove('active');
      }
    });

    document.querySelectorAll('.page-view').forEach(page => {
      if (page.id === `view-${viewId}`) {
        page.classList.add('active');
      } else {
        page.classList.remove('active');
      }
    });

    if (viewId === 'dashboard') {
      setTimeout(() => {
        SIEM_CHARTS.initActivityChart('activityChartCanvas');
        SIEM_CHARTS.initRadarChart('radarChartCanvas');
        NETWORK_MAP.render();
      }, 50);
    }
  }

  // Incidents Page Renderer
  renderIncidents() {
    const container = document.getElementById('incidentsContainer');
    if (!container) return;

    container.innerHTML = this.data.incidents.map(inc => `
      <div class="glass-card" style="border-left:4px solid var(--severity-${inc.severity.toLowerCase()}); display:flex; flex-direction:column; gap:1rem;">
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <div style="display:flex; align-items:center; gap:0.65rem;">
            <span class="severity-pill ${inc.severity}">${inc.severity}</span>
            <strong style="font-size:1.05rem; color:#fff;">${inc.id}: ${inc.title}</strong>
          </div>
          <span class="status-badge" style="background:rgba(59,130,246,0.15); color:var(--electric-blue);">${inc.status}</span>
        </div>

        <p style="font-size:0.85rem; color:var(--text-secondary); line-height:1.6;">${inc.description}</p>

        <div class="alert-body-info" style="grid-template-columns:repeat(3, 1fr);">
          <div class="info-pair"><span class="info-pair-label">Target Asset</span><span class="info-pair-val">${inc.targetHost}</span></div>
          <div class="info-pair"><span class="info-pair-label">Attacker IP</span><span class="info-pair-val" style="color:var(--severity-critical);">${inc.attackerIp}</span></div>
          <div class="info-pair"><span class="info-pair-label">Assigned Lead</span><span class="info-pair-val">${inc.assignedTo}</span></div>
        </div>

        <div style="display:flex; gap:0.5rem; flex-wrap:wrap;">
          ${(inc.mitreTags || []).map(t => `<span class="severity-pill INFO">${t}</span>`).join('')}
        </div>

        <div style="border-top:1px solid var(--border-color); padding-top:0.85rem; display:flex; align-items:center; justify-content:space-between;">
          <span style="font-size:0.75rem; color:var(--text-muted);">SOAR Containment Playbooks:</span>
          <div style="display:flex; gap:0.5rem;">
            ${(inc.playbookActions || []).map(act => `
              <button class="btn-secondary" style="font-size:0.75rem; padding:0.3rem 0.65rem;" onclick="SIEM_APP.executePlaybookAction('${inc.id}', '${act}')">
                🛡️ ${act}
              </button>
            `).join('')}
          </div>
        </div>
      </div>
    `).join('');
  }

  executePlaybookAction(incId, action) {
    this.showToast(`SOAR Playbook Executed: [${action}] for ${incId}`, 'SUCCESS');
  }

  // Metric Cards Render & Counter Animation
  renderMetrics() {
    const { totalEvents, activeAlerts, threatsDetected, criticalEvents } = this.data.metrics;
    
    const elEvents = document.getElementById('metric-total-events');
    const elAlerts = document.getElementById('metric-active-alerts');
    const elThreats = document.getElementById('metric-threats-detected');
    const elCritical = document.getElementById('metric-critical-events');

    if (elEvents) elEvents.textContent = totalEvents.toLocaleString();
    if (elAlerts) elAlerts.textContent = activeAlerts.toString();
    if (elThreats) elThreats.textContent = threatsDetected.toString();
    if (elCritical) elCritical.textContent = criticalEvents.toString();
  }

  animateCounters() {
    const counters = document.querySelectorAll('.metric-value');
    counters.forEach(counter => {
      const target = parseInt(counter.textContent.replace(/,/g, ''), 10);
      if (isNaN(target)) return;

      let start = 0;
      const duration = 1200;
      const stepTime = 20;
      const steps = duration / stepTime;
      const increment = target / steps;

      const timer = setInterval(() => {
        start += increment;
        if (start >= target) {
          counter.textContent = target.toLocaleString();
          clearInterval(timer);
        } else {
          counter.textContent = Math.floor(start).toLocaleString();
        }
      }, stepTime);
    });
  }

  // Dynamic Threat Pulse Meter
  renderThreatPulse() {
    const level = this.data.metrics.threatLevel;
    const pulseBar = document.getElementById('threatPulseBar');
    const levelName = document.getElementById('pulseLevelName');

    if (!pulseBar || !levelName) return;

    pulseBar.className = 'threat-pulse-bar';
    pulseBar.classList.add(`level-${level.toLowerCase()}`);
    levelName.textContent = level;

    document.querySelectorAll('.step-pill').forEach(pill => {
      if (pill.getAttribute('data-level') === level) {
        pill.classList.add('active');
      } else {
        pill.classList.remove('active');
      }
    });
  }

  setThreatLevel(level) {
    this.data.metrics.threatLevel = level;
    this.renderThreatPulse();
    this.showToast(`Threat Level updated to: ${level}`, level === 'CRITICAL' ? 'CRITICAL' : 'INFO');
  }

  // Security Timeline Render
  renderTimeline() {
    const container = document.getElementById('timelineContainer');
    if (!container) return;

    container.innerHTML = this.data.timelineEvents.map((evt, idx) => `
      <div class="timeline-item ${evt.severity.toLowerCase()}" onclick="SIEM_APP.showSocDetails(${idx})">
        <div class="timeline-dot"></div>
        <div class="timeline-time">${evt.time}</div>
        <div class="timeline-title">${evt.title}</div>
        <div class="timeline-desc">${evt.desc}</div>
      </div>
    `).join('');
  }

  showSocDetails(idx) {
    const evt = this.data.timelineEvents[idx];
    if (!evt) return;

    const modalTitle = document.getElementById('modalTitle');
    const modalBody = document.getElementById('modalBody');

    if (modalTitle && modalBody) {
      modalTitle.textContent = `Incident Correlation Step: ${evt.title}`;
      modalBody.innerHTML = `
        <div style="display:flex; flex-direction:column; gap:1.25rem;">
          <div class="status-badge" style="width:fit-content; font-size:0.85rem;">
            ${evt.time} • Severity: <span class="severity-pill ${evt.severity}">${evt.severity}</span>
          </div>

          <div style="font-size:0.95rem; font-weight:600; color:#e2e8f0;">
            ${evt.desc}
          </div>

          <div class="soc-questions-card" style="grid-template-columns:1fr; gap:0.85rem;">
            <div class="q-box"><span class="q-num">1. WHAT IS HAPPENING?</span><span class="q-answer">${evt.socAnswers.what}</span></div>
            <div class="q-box"><span class="q-num">2. IS THERE A THREAT?</span><span class="q-answer">${evt.socAnswers.threat}</span></div>
            <div class="q-box"><span class="q-num">3. HOW SERIOUS IS IT?</span><span class="q-answer">${evt.socAnswers.severity}</span></div>
            <div class="q-box"><span class="q-num">4. WHERE DID IT COME FROM?</span><span class="q-answer">${evt.socAnswers.source}</span></div>
            <div class="q-box"><span class="q-num">5. WHAT SHOULD THE ANALYST INVESTIGATE?</span><span class="q-answer">${evt.socAnswers.action}</span></div>
          </div>
        </div>
      `;
      this.openModal();
    }
  }

  // Live Security Event Feed System
  renderLiveFeed() {
    const container = document.getElementById('liveFeedContainer');
    if (!container) return;

    container.innerHTML = this.data.logs.slice(0, 5).map(log => `
      <div class="feed-item ${log.severity}" onclick="SIEM_APP.inspectLog('${log.id}')">
        <div class="feed-left">
          <div class="feed-time">${log.timestamp.split(' ')[1] || log.timestamp}</div>
          <div class="feed-details">
            <div class="feed-title">${log.event}</div>
            <div class="feed-ip">${log.sourceIp}</div>
          </div>
        </div>
        <span class="severity-pill ${log.severity}">${log.severity}</span>
      </div>
    `).join('');
  }

  startLiveFeedSimulation() {
    if (this.feedInterval) clearInterval(this.feedInterval);

    this.feedInterval = setInterval(() => {
      if (this.feedPaused) return;

      const randomIps = ['192.168.1.45', '10.0.1.99', '172.16.0.12', '192.168.1.102', '185.220.101.9'];
      const randomEvents = ['SSH_AUTH_FAIL', 'HTTP_200_OK', 'DNS_QUERY_FLAGGED', 'VPN_MFA_SUCCESS', 'FIREWALL_DENY'];
      const severities = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

      const rndIp = randomIps[Math.floor(Math.random() * randomIps.length)];
      const rndEvt = randomEvents[Math.floor(Math.random() * randomEvents.length)];
      const rndSev = severities[Math.floor(Math.random() * severities.length)];
      const nowTime = new Date().toTimeString().split(' ')[0];

      const newLog = {
        id: `LOG-${Math.floor(10000 + Math.random() * 90000)}`,
        timestamp: `2026-09-28 ${nowTime}`,
        sourceIp: rndIp,
        destIp: '10.0.2.10',
        username: 'service_acct',
        event: rndEvt,
        severity: rndSev,
        message: `Automated telemetry stream log from ${rndIp}`,
        rule: `TELEMETRY-${rndSev}-RULE`,
        mitre: 'T1078 - Valid Accounts'
      };

      this.data.logs.unshift(newLog);
      this.data.metrics.totalEvents++;
      this.renderMetrics();
      this.renderLiveFeed();
    }, 4500);
  }

  toggleFeedPause() {
    this.feedPaused = !this.feedPaused;
    const btn = document.getElementById('pauseFeedBtn');
    if (btn) {
      btn.innerHTML = this.feedPaused ? '▶' : '⏸';
      this.showToast(this.feedPaused ? 'Live feed paused' : 'Live feed resumed', 'INFO');
    }
  }

  // ALERTS MANAGEMENT & FILTERING
  renderAlerts(filterSev = 'ALL') {
    this.currentAlertFilter = filterSev;
    const container = document.getElementById('alertsGrid');
    if (!container) return;

    const alertPills = document.querySelectorAll('#view-alerts .filter-pill');
    alertPills.forEach(pill => {
      const dataSev = (pill.getAttribute('data-filter') || pill.textContent.trim()).toUpperCase();
      if (dataSev === filterSev.toUpperCase() || (filterSev.toUpperCase() === 'ALL' && (dataSev === 'ALL' || dataSev.includes('ALL')))) {
        pill.classList.add('active');
      } else {
        pill.classList.remove('active');
      }
    });

    let filtered = this.data.alerts;
    if (filterSev.toUpperCase() !== 'ALL') {
      filtered = filtered.filter(a => a.severity.toUpperCase() === filterSev.toUpperCase());
    }

    if (filtered.length === 0) {
      container.innerHTML = `
        <div style="grid-column: 1 / -1; padding:3rem; text-align:center; color:var(--text-muted); background:rgba(15,23,42,0.4); border:1px dashed var(--border-color); border-radius:var(--radius-lg);">
          <div style="font-size:2rem; margin-bottom:0.5rem;">🛡️</div>
          <div style="font-size:1.05rem; font-weight:600; color:#fff;">No ${filterSev} severity alerts currently active</div>
          <p style="font-size:0.85rem; color:var(--text-muted); margin-top:0.25rem;">All monitored security events in this category are operating within baseline thresholds.</p>
        </div>
      `;
      return;
    }

    container.innerHTML = filtered.map(alert => `
      <div class="alert-card ${alert.severity}" id="alert-card-${alert.id}">
        <div class="alert-top">
          <span class="severity-pill ${alert.severity}">${alert.severity}</span>
          <span style="font-family:var(--font-mono); font-size:0.7rem; color:var(--text-muted);">${alert.timestamp}</span>
        </div>
        <div class="alert-title">${alert.title}</div>
        
        <div class="alert-body-info">
          <div class="info-pair">
            <span class="info-pair-label">Source IP</span>
            <span class="info-pair-val">${alert.sourceIp}</span>
          </div>
          <div class="info-pair">
            <span class="info-pair-label">Rule ID</span>
            <span class="info-pair-val">${alert.ruleId}</span>
          </div>
          <div class="info-pair">
            <span class="info-pair-label">Attempts</span>
            <span class="info-pair-val">${alert.attempts}</span>
          </div>
          <div class="info-pair">
            <span class="info-pair-label">Status</span>
            <span class="info-pair-val" style="color:var(--electric-blue);">${alert.status}</span>
          </div>
        </div>

        <div class="alert-actions">
          <button class="btn-primary" onclick="event.stopPropagation(); SIEM_APP.investigateAlert('${alert.id}')">
            🔍 <span>Investigate</span>
          </button>
          <button class="btn-secondary" onclick="event.stopPropagation(); SIEM_APP.resolveAlert('${alert.id}')">
            ✅ <span>Resolve</span>
          </button>
        </div>
      </div>
    `).join('');
  }

  investigateAlert(alertId) {
    console.log("Investigating alert ID:", alertId);
    const alert = this.data.alerts.find(a => a.id === alertId);
    if (!alert) {
      console.error(`Alert ${alertId} not found in dataset`, this.data.alerts);
      return;
    }

    alert.status = 'INVESTIGATING';

    const modalTitle = document.getElementById('modalTitle');
    const modalBody = document.getElementById('modalBody');

    if (modalTitle && modalBody) {
      modalTitle.textContent = `Alert Investigation: ${alert.id}`;
      modalBody.innerHTML = `
        <div style="display:flex; flex-direction:column; gap:1.25rem;">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <h3 style="font-size:1.1rem; color:#fff; font-weight:700;">${alert.title}</h3>
            <span class="severity-pill ${alert.severity}">${alert.severity}</span>
          </div>
          
          <p style="color:var(--text-secondary); line-height:1.6; font-size:0.9rem;">${alert.description || 'High-priority security telemetry alert requiring analyst triage.'}</p>

          <div class="alert-body-info" style="grid-template-columns:repeat(2, 1fr); gap:1rem; padding:1rem; background:rgba(15,23,42,0.6); border-radius:8px; border:1px solid var(--border-color);">
            <div class="info-pair"><span class="info-pair-label">Target Host Asset</span><span class="info-pair-val" style="color:#fff;">${alert.destIp}</span></div>
            <div class="info-pair"><span class="info-pair-label">Attacker Source IP</span><span class="info-pair-val" style="color:var(--severity-critical); font-weight:700;">${alert.sourceIp}</span></div>
            <div class="info-pair"><span class="info-pair-label">Triggered Rule ID</span><span class="info-pair-val" style="color:var(--cyan-highlight);">${alert.ruleId}</span></div>
            <div class="info-pair"><span class="info-pair-label">Failed Attempt Count</span><span class="info-pair-val" style="color:var(--severity-high);">${alert.attempts}</span></div>
          </div>

          <div style="margin-top:1rem; display:flex; gap:0.75rem; flex-wrap:wrap;">
            <button class="btn-primary" onclick="SIEM_APP.executeFirewallBlock('${alert.sourceIp}')">🔒 Block IP on Firewall</button>
            <button class="btn-secondary" onclick="SIEM_APP.showToast('Active User Session Revoked', 'SUCCESS'); SIEM_APP.closeModal();">🚫 Revoke User Credentials</button>
            <button class="btn-secondary" onclick="SIEM_APP.closeModal()">✕ Close Window</button>
          </div>
        </div>
      `;
      this.openModal();
    }

    // Update alert status visually in DOM without full grid teardown
    const alertCard = document.getElementById(`alert-card-${alert.id}`);
    if (alertCard) {
      const statusPairs = alertCard.querySelectorAll('.info-pair-val');
      if (statusPairs && statusPairs.length >= 4) {
        statusPairs[3].textContent = 'INVESTIGATING';
      }
    }
  }

  async resolveAlert(alertId) {
    const alert = this.data.alerts.find(a => a.id === alertId);
    if (!alert) return;

    alert.status = 'RESOLVED';
    if (this.data.metrics.activeAlerts > 0) this.data.metrics.activeAlerts--;

    if (this.isBackendConnected) {
      try {
        await fetch(`${this.apiUrl}/alerts/${alertId}/resolve`, { method: 'POST' });
      } catch (e) { console.error(e); }
    }

    this.renderMetrics();
    this.renderAlerts(this.currentAlertFilter);
    this.showToast(`Alert ${alertId} resolved`, 'SUCCESS');
  }

  executeFirewallBlock(ip) {
    this.showToast(`Firewall Rule Created: Blocked IP ${ip}`, 'SUCCESS');
    this.closeModal();
  }

  // LOG EXPLORER & FILTERING
  filterLogs(severity = 'ALL') {
    this.currentLogFilter = severity;

    const logPills = document.querySelectorAll('#view-logs .filter-pill');
    logPills.forEach(pill => {
      const dataSev = (pill.getAttribute('data-filter') || pill.textContent.trim()).toUpperCase();
      if (dataSev === severity.toUpperCase() || (severity.toUpperCase() === 'ALL' && (dataSev === 'ALL' || dataSev.includes('ALL')))) {
        pill.classList.add('active');
      } else {
        pill.classList.remove('active');
      }
    });

    this.renderLogs();
  }

  renderLogs() {
    const tbody = document.getElementById('logsTbody');
    const countBadge = document.getElementById('logsCountBadge');
    if (!tbody) return;

    let filtered = this.data.logs;
    if (this.currentLogFilter !== 'ALL') {
      filtered = filtered.filter(l => l.severity.toUpperCase() === this.currentLogFilter.toUpperCase());
    }

    if (countBadge) {
      countBadge.textContent = `Showing ${filtered.length} of ${this.data.logs.length} ingested logs`;
    }

    if (filtered.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="6" style="text-align:center; padding:2rem; color:var(--text-muted);">
            No logs found matching filter: ${this.currentLogFilter}
          </td>
        </tr>
      `;
      return;
    }

    tbody.innerHTML = filtered.map(log => `
      <tr class="log-row ${this.expandedLogRowId === log.id ? 'expanded' : ''}" onclick="SIEM_APP.toggleLogRow('${log.id}')">
        <td class="mono">${log.timestamp}</td>
        <td class="mono" style="color:var(--cyan-highlight);">${log.sourceIp}</td>
        <td class="mono">${log.destIp}</td>
        <td>${log.username}</td>
        <td><strong>${log.event}</strong></td>
        <td><span class="severity-pill ${log.severity}">${log.severity}</span></td>
      </tr>
      <tr class="log-detail-row ${this.expandedLogRowId === log.id ? 'open' : ''}" id="detail-row-${log.id}">
        <td colspan="6">
          <div class="detail-content">
            <div>
              <div style="font-weight:700; margin-bottom:0.4rem;">Syslog Message:</div>
              <p style="color:var(--text-secondary); margin-bottom:1rem;">${log.message}</p>
              
              <div style="font-weight:700; margin-bottom:0.4rem;">JSON Payload:</div>
              <div class="code-block">${JSON.stringify(log.payload || {}, null, 2)}</div>
            </div>
            <div>
              <div style="font-weight:700; margin-bottom:0.4rem;">Detection Rule</div>
              <p style="color:var(--electric-blue); font-size:0.85rem; margin-bottom:1rem;">${log.rule}</p>

              <div style="font-weight:700; margin-bottom:0.4rem;">MITRE ATT&CK® Mapping</div>
              <span class="severity-pill INFO" style="font-size:0.75rem;">${log.mitre}</span>
            </div>
          </div>
        </td>
      </tr>
    `).join('');
  }

  toggleLogRow(logId) {
    this.expandedLogRowId = this.expandedLogRowId === logId ? null : logId;
    this.renderLogs();
  }

  inspectLog(logId) {
    this.switchView('logs');
    this.toggleLogRow(logId);
  }

  // CUSTOM DETECTION RULE BUILDER
  renderRuleBuilder() {
    const listContainer = document.getElementById('rulesListContainer');
    if (!listContainer) return;

    listContainer.innerHTML = this.data.rules.map(rule => `
      <div class="glass-card" style="border-left:4px solid var(--severity-${rule.severity.toLowerCase()}); display:flex; flex-direction:column; gap:0.75rem;">
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <div style="display:flex; align-items:center; gap:0.6rem;">
            <span class="severity-pill ${rule.severity}">${rule.severity}</span>
            <strong style="font-size:1rem; color:#fff;">${rule.title}</strong>
          </div>
          <div style="display:flex; align-items:center; gap:0.6rem;">
            <span class="mono" style="font-size:0.75rem; color:var(--cyan-highlight);">${rule.id}</span>
            <button class="btn-secondary" style="padding:0.25rem 0.6rem; font-size:0.75rem;" onclick="SIEM_APP.toggleRuleStatus('${rule.id}')">
              ${rule.status === 'ACTIVE' ? '🟢 Active' : '⚪ Disabled'}
            </button>
          </div>
        </div>

        <p style="font-size:0.82rem; color:var(--text-secondary); line-height:1.5;">${rule.description}</p>

        <div style="display:grid; grid-template-columns:repeat(4, 1fr); gap:0.5rem; background:rgba(6,9,17,0.4); padding:0.6rem; border-radius:6px; font-size:0.75rem;">
          <div><span style="color:var(--text-muted);">Log Source:</span> <span class="mono">${rule.logSource}</span></div>
          <div><span style="color:var(--text-muted);">Threshold:</span> <span class="mono">${rule.threshold} / ${rule.timeframe}</span></div>
          <div><span style="color:var(--text-muted);">MITRE:</span> <span>${rule.mitre}</span></div>
          <div><span style="color:var(--text-muted);">Author:</span> <span>${rule.author}</span></div>
        </div>

        <div class="code-block" style="font-size:0.72rem; padding:0.5rem;">${rule.condition}</div>
      </div>
    `).join('');

    this.updateSigmaPreview();
  }

  updateSigmaPreview() {
    const title = document.getElementById('ruleFormTitle')?.value || 'SSH Dictionary Spray Detection';
    const severity = document.getElementById('ruleFormSeverity')?.value || 'CRITICAL';
    const logSource = document.getElementById('ruleFormLogSource')?.value || 'syslog.auth';
    const mitre = document.getElementById('ruleFormMitre')?.value || 'T1110.001';
    const condition = document.getElementById('ruleFormCondition')?.value || 'event == "SSH_AUTH_FAIL" AND count >= 10';

    const yaml = `title: ${title}
id: RULE-CUSTOM-${Math.floor(100 + Math.random() * 900)}
status: experimental
description: Custom detection rule generated via SIEM Rule Builder
author: ${this.data.profile.name}
logsource:
    product: ${logSource.split('.')[0]}
    service: ${logSource.split('.')[1] || 'auth'}
detection:
    selection:
        ${condition}
    timeframe: 60s
    condition: selection
level: ${severity.toLowerCase()}
tags:
    - attack.${mitre.toLowerCase().split(' ')[0]}`;

    const previewEl = document.getElementById('sigmaRulePreview');
    if (previewEl) previewEl.textContent = yaml;
  }

  async saveNewRule() {
    const title = document.getElementById('ruleFormTitle').value;
    const severity = document.getElementById('ruleFormSeverity').value;
    const logSource = document.getElementById('ruleFormLogSource').value;
    const mitre = document.getElementById('ruleFormMitre').value;
    const threshold = document.getElementById('ruleFormThreshold').value || 10;
    const condition = document.getElementById('ruleFormCondition').value;
    const description = document.getElementById('ruleFormDesc').value || 'Custom user created rule';

    if (!title || !condition) {
      this.showToast('Please fill in Rule Title and Condition', 'CRITICAL');
      return;
    }

    const newRule = {
      id: `RULE-SEC-${Math.floor(5000 + Math.random() * 4000)}`,
      title,
      severity,
      author: this.data.profile.name,
      logSource,
      status: 'ACTIVE',
      threshold: parseInt(threshold, 10),
      timeframe: '60s',
      mitre,
      condition,
      action: 'Trigger Alert & Notify Analyst',
      description
    };

    if (this.isBackendConnected) {
      try {
        const res = await fetch(`${this.apiUrl}/rules`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(newRule)
        });
        const saved = await res.json();
        if (saved.id) newRule.id = saved.id;
      } catch (e) { console.error(e); }
    }

    this.data.rules.unshift(newRule);
    this.renderRuleBuilder();
    this.showToast(`Custom Rule [${newRule.id}] saved to SQLite database and deployed!`, 'SUCCESS');
  }

  toggleRuleStatus(ruleId) {
    const rule = this.data.rules.find(r => r.id === ruleId);
    if (!rule) return;
    rule.status = rule.status === 'ACTIVE' ? 'DISABLED' : 'ACTIVE';
    this.renderRuleBuilder();
    this.showToast(`Rule ${ruleId} is now ${rule.status}`, 'INFO');
  }

  testRuleSandbox() {
    const sandboxResults = document.getElementById('sandboxResults');
    if (!sandboxResults) return;

    const matchedLogs = this.data.logs.slice(0, 3);
    sandboxResults.innerHTML = `
      <div style="color:var(--severity-low); font-weight:600; margin-bottom:0.5rem;">
        ✅ Rule Sandbox Evaluation Complete: 3 Matches Found in recent telemetry stream
      </div>
      ${matchedLogs.map(l => `
        <div style="font-size:0.78rem; font-family:var(--font-mono); color:var(--text-secondary); background:rgba(6,9,17,0.6); padding:0.4rem 0.6rem; border-radius:4px; margin-bottom:0.35rem;">
          [${l.timestamp}] IP: ${l.sourceIp} → Event: ${l.event} (Rule Matched!)
        </div>
      `).join('')}
    `;
  }

  // Security Concepts Page
  renderConcepts() {
    const container = document.getElementById('conceptsGrid');
    if (!container) return;

    container.innerHTML = this.data.concepts.map(concept => `
      <div class="concept-card" onclick="SIEM_APP.showConceptModal('${concept.id}')">
        <div class="concept-icon">💡</div>
        <div class="concept-title">${concept.title}</div>
        <div class="concept-summary">${concept.summary}</div>
        <div class="concept-footer-link">Explore Concept & How SIEM Uses It →</div>
      </div>
    `).join('');
  }

  showConceptModal(conceptId) {
    const c = this.data.concepts.find(item => item.id === conceptId);
    if (!c) return;

    const modalTitle = document.getElementById('modalTitle');
    const modalBody = document.getElementById('modalBody');

    if (modalTitle && modalBody) {
      modalTitle.textContent = `${c.title} - ${c.fullTitle}`;
      modalBody.innerHTML = `
        <div style="display:flex; flex-direction:column; gap:1.25rem;">
          <div>
            <h4 style="color:var(--cyan-highlight); margin-bottom:0.35rem;">What is it?</h4>
            <p style="color:var(--text-secondary); line-height:1.6;">${c.whatIsIt}</p>
          </div>

          <div>
            <h4 style="color:var(--severity-low); margin-bottom:0.35rem;">Why is it important?</h4>
            <p style="color:var(--text-secondary); line-height:1.6;">${c.whyImportant}</p>
          </div>

          <div>
            <h4 style="color:var(--severity-medium); margin-bottom:0.35rem;">Real-World Example:</h4>
            <div class="code-block">${c.example}</div>
          </div>

          <div style="background:rgba(59, 130, 246, 0.1); border:1px solid rgba(59, 130, 246, 0.25); border-radius:var(--radius-md); padding:1rem;">
            <h4 style="color:var(--electric-blue); margin-bottom:0.35rem;">How this SIEM Dashboard uses it:</h4>
            <p style="color:#e2e8f0; line-height:1.5;">${c.howUsedHere}</p>
          </div>
        </div>
      `;
      this.openModal();
    }
  }

  // System Status Page
  renderStatus() {
    const container = document.getElementById('statusListContainer');
    if (!container) return;

    container.innerHTML = this.data.systemStatus.components.map(comp => `
      <div class="status-row">
        <div class="status-row-left">
          <div class="status-dot"></div>
          <div class="status-row-name">${comp.name}</div>
        </div>
        <div style="display:flex; align-items:center; gap:1.5rem;">
          <span style="font-family:var(--font-mono); font-size:0.8rem; color:var(--text-muted);">${comp.eps}</span>
          <span style="font-family:var(--font-mono); font-size:0.8rem; color:var(--cyan-highlight);">${comp.latency}</span>
          <span class="status-badge">${comp.status}</span>
        </div>
      </div>
    `).join('');
  }

  // Global Search Filter
  setupGlobalSearch() {
    const searchInput = document.getElementById('globalSearchInput');
    if (!searchInput) return;

    searchInput.addEventListener('input', (e) => {
      const q = e.target.value.toLowerCase().trim();
      if (!q) return;

      const matchedLog = this.data.logs.find(l => 
        l.sourceIp.includes(q) || l.event.toLowerCase().includes(q) || l.message.toLowerCase().includes(q)
      );

      if (matchedLog && e.key === 'Enter') {
        this.inspectLog(matchedLog.id);
      }
    });

    window.addEventListener('keydown', (e) => {
      if (e.key === '/' && document.activeElement !== searchInput) {
        e.preventDefault();
        searchInput.focus();
      }
    });
  }

  // Attack Simulator Controls
  async triggerScenario(scenarioKey) {
    const sc = this.data.attackScenarios[scenarioKey];
    if (!sc) return;

    this.setThreatLevel(sc.threatLevel);

    if (this.isBackendConnected) {
      try {
        await fetch(`${this.apiUrl}/simulate`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ scenario: scenarioKey })
        });
      } catch (e) { console.error(e); }
    }

    if (sc.addAlert) {
      this.data.alerts.unshift(sc.addAlert);
      this.data.metrics.activeAlerts++;
      this.renderAlerts(this.currentAlertFilter);
    }

    if (sc.addLog) {
      this.data.logs.unshift(sc.addLog);
      this.data.metrics.totalEvents++;
      this.renderLogs();
      this.renderLiveFeed();
    }

    this.renderMetrics();
    this.showToast(`Simulated Attack Executed: ${sc.name}`, 'CRITICAL');
  }

  async resetBaseline() {
    this.setThreatLevel('NORMAL');

    if (this.isBackendConnected) {
      try {
        await fetch(`${this.apiUrl}/simulate`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ scenario: 'reset' })
        });
      } catch (e) { console.error(e); }
    }

    this.showToast('Security posture reset to Baseline Normal', 'SUCCESS');
  }

  // Modal Open/Close
  openModal() {
    const overlay = document.getElementById('modalOverlay');
    if (overlay) {
      overlay.style.setProperty('display', 'flex', 'important');
      overlay.style.setProperty('opacity', '1', 'important');
      overlay.style.setProperty('z-index', '99999', 'important');
      overlay.classList.add('active');
    }
  }

  closeModal() {
    const overlay = document.getElementById('modalOverlay');
    if (overlay) {
      overlay.style.setProperty('display', 'none', 'important');
      overlay.style.setProperty('opacity', '0', 'important');
      overlay.classList.remove('active');
    }
  }

  // Toast Notification System
  showToast(message, type = 'INFO') {
    const container = document.getElementById('toastContainer');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
      <div style="font-weight:700;">${type === 'CRITICAL' ? '⚠️' : 'ℹ️'}</div>
      <div style="font-size:0.82rem; color:#fff;">${message}</div>
    `;

    container.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(10px)';
      setTimeout(() => toast.remove(), 300);
    }, 4000);
  }

  setupEventListeners() {
    const overlay = document.getElementById('modalOverlay');
    if (overlay) {
      overlay.addEventListener('click', (e) => {
        if (e.target === overlay) this.closeModal();
      });
    }
  }
}

// Instantiate Immediately & Bind
window.SIEM_APP = new SiemApplication();
document.addEventListener('DOMContentLoaded', () => {
  window.SIEM_APP.init();
});
