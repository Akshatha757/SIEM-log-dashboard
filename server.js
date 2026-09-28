/* ==========================================================================
   SIEM LOG DASHBOARD - Node.js Express REST API & SQLite Database Backend
   ========================================================================== */

const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const PORT = process.env.PORT || 5000;
const DB_PATH = path.join(__dirname, 'siem_database.db');

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, './')));

// Initialize SQLite Database
const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) {
    console.error('Error opening SQLite database:', err.message);
  } else {
    console.log('Connected to SQLite database: siem_database.db');
    initDatabaseSchema();
  }
});

// Database Migration & Schema Setup
function initDatabaseSchema() {
  db.serialize(() => {
    // 1. Profile Table
    db.run(`CREATE TABLE IF NOT EXISTS profile (
      id INTEGER PRIMARY KEY,
      name TEXT,
      initials TEXT,
      role TEXT,
      status TEXT
    )`);

    // 2. Metrics Table
    db.run(`CREATE TABLE IF NOT EXISTS metrics (
      id INTEGER PRIMARY KEY,
      total_events INTEGER,
      active_alerts INTEGER,
      threats_detected INTEGER,
      critical_events INTEGER,
      threat_level TEXT
    )`);

    // 3. Logs Table
    db.run(`CREATE TABLE IF NOT EXISTS logs (
      id TEXT PRIMARY KEY,
      timestamp TEXT,
      source_ip TEXT,
      dest_ip TEXT,
      username TEXT,
      event TEXT,
      severity TEXT,
      message TEXT,
      rule TEXT,
      mitre TEXT,
      payload TEXT
    )`);

    // 4. Alerts Table
    db.run(`CREATE TABLE IF NOT EXISTS alerts (
      id TEXT PRIMARY KEY,
      title TEXT,
      severity TEXT,
      rule_id TEXT,
      source_ip TEXT,
      dest_ip TEXT,
      attempts INTEGER,
      timestamp TEXT,
      status TEXT,
      description TEXT
    )`);

    // 5. Rules Table
    db.run(`CREATE TABLE IF NOT EXISTS rules (
      id TEXT PRIMARY KEY,
      title TEXT,
      author TEXT,
      severity TEXT,
      log_source TEXT,
      status TEXT,
      threshold INTEGER,
      timeframe TEXT,
      mitre TEXT,
      condition TEXT,
      action TEXT,
      description TEXT
    )`);

    // 6. Incidents Table
    db.run(`CREATE TABLE IF NOT EXISTS incidents (
      id TEXT PRIMARY KEY,
      title TEXT,
      severity TEXT,
      status TEXT,
      target_host TEXT,
      attacker_ip TEXT,
      assigned_to TEXT,
      timestamp TEXT,
      mitre_tags TEXT,
      description TEXT,
      playbook_actions TEXT
    )`);

    seedInitialData();
  });
}

// Seed Initial Portfolio Data if Tables are Empty
function seedInitialData() {
  db.get('SELECT COUNT(*) as count FROM profile', (err, row) => {
    if (row && row.count === 0) {
      db.run(`INSERT INTO profile (id, name, initials, role, status) VALUES (1, 'Cybersecurity Analyst', 'CA', 'Portfolio Security Developer', 'Active Duty')`);
    }
  });

  db.get('SELECT COUNT(*) as count FROM metrics', (err, row) => {
    if (row && row.count === 0) {
      db.run(`INSERT INTO metrics (id, total_events, active_alerts, threats_detected, critical_events, threat_level) VALUES (1, 12458, 24, 8, 3, 'ELEVATED')`);
    }
  });

  db.get('SELECT COUNT(*) as count FROM incidents', (err, row) => {
    if (row && row.count === 0) {
      const initialIncidents = [
        ['INC-2026-089', 'Credential Spray & Lateral Movement Campaign', 'CRITICAL', 'INVESTIGATING', 'DB-PROD-01 (10.0.2.10)', '192.168.1.50', 'SOC Lead Analyst', 'Today 09:42', JSON.stringify(["T1110 - Brute Force", "T1548.003 - Sudo Caching", "T1078 - Valid Accounts"]), 'Multi-vector adversary campaign targeting SSH service followed by unauthorized sudo escalation.', JSON.stringify(["Isolate Host Subnet", "Block Attacker IP on Firewall", "Revoke Active User Tokens"])],
        ['INC-2026-074', 'High-Volume Data Exfiltration via Tor Exit Node', 'HIGH', 'CONTAINED', 'WORKSTATION-FINANCE (10.0.1.88)', '185.220.101.4', 'Network Forensics Team', 'Today 09:15', JSON.stringify(["T1041 - Exfiltration Over C2 Channel", "T1071 - Application Layer Protocol"]), 'Compressed encrypted payload (4.2GB) transmitted to Tor exit node.', JSON.stringify(["Block Attacker IP on Firewall", "Revoke Active User Tokens"])]
      ];
      const stmt = db.prepare(`INSERT INTO incidents VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
      initialIncidents.forEach(inc => stmt.run(inc));
      stmt.finalize();
    }
  });

  db.get('SELECT COUNT(*) as count FROM rules', (err, row) => {
    if (row && row.count === 0) {
      const initialRules = [
        ['RULE-SEC-4021', 'SSH Brute Force Attack Threshold', 'SOC Analyst', 'CRITICAL', 'syslog.auth', 'ACTIVE', 15, '60s', 'T1110.001', 'event == "SSH_AUTH_FAIL" AND attempts >= 15', 'Trigger Critical Alert & SOAR Containment', 'Detects 15+ consecutive SSH auth failures in 60s.'],
        ['RULE-PRIV-109', 'Unauthorized Sudo Privilege Escalation', 'Threat Intel Team', 'CRITICAL', 'linux.secure', 'ACTIVE', 1, 'Immediate', 'T1548.003', 'event == "SUDO_EXEC_DENIED" AND user != "root"', 'Trigger Critical Alert & Session Lock', 'Detects non-authorized service accounts attempting sudo.'],
        ['RULE-EXFIL-302', 'Suspicious Outbound Payload Volume', 'Network Security Team', 'HIGH', 'firewall.paloalto', 'ACTIVE', 1000, '300s', 'T1041', 'bytesSent > 1073741824 AND destIp IN threat_intel_feed', 'Trigger High Alert & Quarantine Connection', 'Detects outbound data transfers exceeding 1GB to Tor exit nodes.'],
        ['RULE-WEB-201', 'Web App Authentication Spray', 'AppSec Analyst', 'MEDIUM', 'nginx.access', 'ACTIVE', 10, '120s', 'T1078', 'httpStatus == 401 AND endpoint == "/api/v1/auth/login"', 'Trigger Medium Alert & Rate Limit IP', 'Detects rapid HTTP 401 Unauthorized responses targeting auth endpoints.']
      ];
      const stmt = db.prepare(`INSERT INTO rules (id, title, author, severity, log_source, status, threshold, timeframe, mitre, condition, action, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
      initialRules.forEach(r => stmt.run(r));
      stmt.finalize();
    }
  });

  db.get('SELECT COUNT(*) as count FROM logs', (err, row) => {
    if (row && row.count === 0) {
      const initialLogs = [
        ['LOG-99201', '2026-09-28 09:42:31', '192.168.1.50', '10.0.2.10', 'root', 'SSH_AUTH_FAIL', 'CRITICAL', 'Failed password for root from 192.168.1.50 port 52310 ssh2', 'SEC-4021: SSH Brute Force Threshold', 'T1110.001 - Password Guessing', JSON.stringify({ protocol: 'SSHv2', failCount: 45, targetHost: 'DB-PROD-01' })],
        ['LOG-99188', '2026-09-28 09:40:15', '10.0.4.15', '10.0.4.15', 'app-service', 'SUDO_EXEC_DENIED', 'CRITICAL', 'app-service : TTY=pts/1 ; PWD=/var/www ; USER=root ; COMMAND=/bin/bash', 'PRIV-109: Unauthorized Sudo Escalation', 'T1548.003 - Sudo Caching', JSON.stringify({ attemptedUser: 'root', binary: '/bin/bash' })],
        ['LOG-99152', '2026-09-28 09:35:02', '10.0.1.88', '185.220.101.4', 'finance_user', 'DATA_EXFIL_DETECTED', 'HIGH', 'Outbound connection to known Tor Exit Node 185.220.101.4 (4.2GB transfer)', 'EXFIL-302: Suspicious Outbound Volume', 'T1041 - Exfiltration Over C2 Channel', JSON.stringify({ bytesTransferred: 4509715200, protocol: 'HTTPS' })],
        ['LOG-99110', '2026-09-28 09:12:44', '192.168.1.25', '10.0.0.0/24', 'system', 'NMAP_SYN_SCAN', 'MEDIUM', 'TCP SYN Scan across 1024 ports from 192.168.1.25', 'NET-504: Reconnaissance Port Scan', 'T1595 - Active Scanning', JSON.stringify({ scannedPorts: 1024, duration: '12s' })],
        ['LOG-99084', '2026-09-28 08:55:10', '172.16.0.42', '10.0.1.5', 'guest', 'HTTP_AUTH_FAILURE', 'MEDIUM', 'HTTP 401 Unauthorized POST request to /admin/login endpoint', 'WEB-201: Web App Auth Spray', 'T1078 - Valid Accounts', JSON.stringify({ endpoint: '/admin/login', statusCode: 401 })],
        ['LOG-99042', '2026-09-28 08:30:00', '10.0.1.12', '10.0.1.10', 'ad_admin', 'ACTIVE_DIRECTORY_USER_ADDED', 'HIGH', 'User j_smith added to Domain Admins security group', 'IAM-102: Privilege Escalation', 'T1098 - Account Manipulation', JSON.stringify({ addedUser: 'j_smith', group: 'Domain Admins' })],
        ['LOG-98990', '2026-09-28 08:15:22', '192.168.1.100', '10.0.0.1', 'employee1', 'VPN_MFA_SUCCESS', 'INFO', 'User employee1 authenticated successfully via Duo MFA', 'VPN-100: Normal VPN Login', 'T1078 - Valid Accounts', JSON.stringify({ location: 'Remote Access VPN', mfaMethod: 'Duo Push' })]
      ];
      const stmt = db.prepare(`INSERT INTO logs (id, timestamp, source_ip, dest_ip, username, event, severity, message, rule, mitre, payload) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
      initialLogs.forEach(l => stmt.run(l));
      stmt.finalize();
    }
  });

  db.get('SELECT COUNT(*) as count FROM alerts', (err, row) => {
    if (row && row.count === 0) {
      const initialAlerts = [
        ['ALT-2026-901', 'SSH Brute Force Attack Detected', 'CRITICAL', 'RULE-SEC-4021', '192.168.1.50', '10.0.2.10', 45, '2 mins ago', 'OPEN', 'High volume of failed SSH login attempts targeting production DB server within 60s.'],
        ['ALT-2026-894', 'Privilege Escalation via Sudo', 'CRITICAL', 'RULE-PRIV-109', '10.0.4.15', '10.0.4.15', 1, '12 mins ago', 'INVESTIGATING', 'Non-standard user app-service attempted sudo execution of /bin/bash without valid ticket.'],
        ['ALT-2026-882', 'Unusual Outbound Data Transfer', 'HIGH', 'RULE-EXFIL-302', '10.0.1.88', '185.220.101.4', 3, '28 mins ago', 'OPEN', 'Host transmitted 4.2 GB of encrypted compressed payload to unverified external Tor exit node.'],
        ['ALT-2026-879', 'Port Scan Activity (Nmap)', 'MEDIUM', 'RULE-NET-504', '192.168.1.25', '10.0.0.0/24', 1024, '45 mins ago', 'OPEN', 'Sequential SYN scan detected across 1,024 TCP ports targeting internal server subnet.'],
        ['ALT-2026-865', 'Multiple Failed Web Admin Logins', 'MEDIUM', 'RULE-WEB-201', '172.16.0.42', '10.0.1.5', 12, '1 hour ago', 'RESOLVED', 'Failed HTTP POST authentication on /admin/login endpoint with invalid CSRF tokens.'],
        ['ALT-2026-850', 'New Domain Admin User Created', 'HIGH', 'RULE-IAM-102', '10.0.1.12', '10.0.1.10', 1, '2 hours ago', 'OPEN', 'Unauthorized active directory account privilege escalation to Enterprise Admin group.']
      ];
      const stmt = db.prepare(`INSERT INTO alerts (id, title, severity, rule_id, source_ip, dest_ip, attempts, timestamp, status, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
      initialAlerts.forEach(a => stmt.run(a));
      stmt.finalize();
    }
  });
}

// REST API ENDPOINTS
app.get('/api/metrics', (req, res) => {
  db.get('SELECT * FROM metrics WHERE id = 1', (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({
      totalEvents: row ? row.total_events : 12458,
      activeAlerts: row ? row.active_alerts : 24,
      threatsDetected: row ? row.threats_detected : 8,
      criticalEvents: row ? row.critical_events : 3,
      threatLevel: row ? row.threat_level : 'ELEVATED'
    });
  });
});

app.get('/api/incidents', (req, res) => {
  db.all('SELECT * FROM incidents ORDER BY id DESC', [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    const formatted = rows.map(r => ({
      id: r.id,
      title: r.title,
      severity: r.severity,
      status: r.status,
      targetHost: r.target_host,
      attackerIp: r.attacker_ip,
      assignedTo: r.assigned_to,
      timestamp: r.timestamp,
      mitreTags: JSON.parse(r.mitre_tags || '[]'),
      description: r.description,
      playbookActions: JSON.parse(r.playbook_actions || '[]')
    }));
    res.json(formatted);
  });
});

app.get('/api/profile', (req, res) => {
  db.get('SELECT * FROM profile WHERE id = 1', (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(row);
  });
});

app.post('/api/profile', (req, res) => {
  const { name, initials, role } = req.body;
  db.run('UPDATE profile SET name = ?, initials = ?, role = ? WHERE id = 1', [name, initials, role], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true, name, initials, role });
  });
});

app.get('/api/logs', (req, res) => {
  const { severity, limit = 50 } = req.query;
  let query = 'SELECT * FROM logs';
  let params = [];

  if (severity) {
    query += ' WHERE severity = ?';
    params.push(severity);
  }
  query += ' ORDER BY timestamp DESC LIMIT ?';
  params.push(parseInt(limit, 10));

  db.all(query, params, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    const formatted = rows.map(r => ({
      id: r.id,
      timestamp: r.timestamp,
      sourceIp: r.source_ip,
      destIp: r.dest_ip,
      username: r.username,
      event: r.event,
      severity: r.severity,
      message: r.message,
      rule: r.rule,
      mitre: r.mitre,
      payload: JSON.parse(r.payload || '{}')
    }));
    res.json(formatted);
  });
});

app.get('/api/alerts', (req, res) => {
  db.all('SELECT * FROM alerts ORDER BY id DESC', [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    const formatted = rows.map(r => ({
      id: r.id,
      title: r.title,
      severity: r.severity,
      ruleId: r.rule_id,
      sourceIp: r.source_ip,
      destIp: r.dest_ip,
      attempts: r.attempts,
      timestamp: r.timestamp,
      status: r.status,
      description: r.description
    }));
    res.json(formatted);
  });
});

app.post('/api/alerts/:id/resolve', (req, res) => {
  const alertId = req.params.id;
  db.run("UPDATE alerts SET status = 'RESOLVED' WHERE id = ?", [alertId], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true, alertId, status: 'RESOLVED' });
  });
});

app.get('/api/rules', (req, res) => {
  db.all('SELECT * FROM rules ORDER BY id DESC', [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    const formatted = rows.map(r => ({
      id: r.id,
      title: r.title,
      author: r.author,
      severity: r.severity,
      logSource: r.log_source,
      status: r.status,
      threshold: r.threshold,
      timeframe: r.timeframe,
      mitre: r.mitre,
      condition: r.condition,
      action: r.action,
      description: r.description
    }));
    res.json(formatted);
  });
});

app.post('/api/rules', (req, res) => {
  const { title, author, severity, logSource, threshold, timeframe = '60s', mitre, condition, description } = req.body;
  const id = `RULE-SEC-${Math.floor(5000 + Math.random() * 4000)}`;
  const action = 'Trigger Alert & Notify Analyst';

  db.run(
    `INSERT INTO rules (id, title, author, severity, log_source, status, threshold, timeframe, mitre, condition, action, description) 
     VALUES (?, ?, ?, ?, ?, 'ACTIVE', ?, ?, ?, ?, ?, ?)`,
    [id, title, author, severity, logSource, threshold, timeframe, mitre, condition, action, description],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true, id, title, severity, status: 'ACTIVE' });
    }
  );
});

app.post('/api/simulate', (req, res) => {
  const { scenario } = req.body;

  if (scenario === 'bruteForce') {
    const alertId = `ALT-SIM-${Math.floor(100 + Math.random() * 900)}`;
    const logId = `LOG-SIM-${Math.floor(100 + Math.random() * 900)}`;
    const nowTime = new Date().toTimeString().split(' ')[0];

    db.run("INSERT INTO alerts VALUES (?, 'CRITICAL: Active Password Spray Attack', 'CRITICAL', 'RULE-SEC-4021', '45.142.214.10', '10.0.0.5', 180, 'Just now', 'OPEN', 'SSH dictionary attack targeting domain accounts')", [alertId]);
    db.run("INSERT INTO logs VALUES (?, ?, '45.142.214.10', '10.0.0.5', 'admin_root', 'SSH_BRUTE_FORCE_BURST', 'CRITICAL', 'ALERT: 180 failed auth attempts from 45.142.214.10', 'SEC-4021', 'T1110.003', ?)", [logId, `2026-09-28 ${nowTime}`, JSON.stringify({ attempts: 180 })]);
    db.run("UPDATE metrics SET threat_level = 'CRITICAL', active_alerts = active_alerts + 1, total_events = total_events + 1 WHERE id = 1");

    return res.json({ success: true, scenario: 'bruteForce', threatLevel: 'CRITICAL', alertId });
  }

  if (scenario === 'reset') {
    db.run("UPDATE metrics SET threat_level = 'NORMAL' WHERE id = 1");
    return res.json({ success: true, scenario: 'reset', threatLevel: 'NORMAL' });
  }

  res.json({ success: true, scenario });
});

app.listen(PORT, () => {
  console.log(`=======================================================`);
  console.log(`🛡️  SIEM Log Dashboard Node.js REST API Server Running`);
  console.log(`🌐 Server URL: http://localhost:${PORT}`);
  console.log(`💾 SQLite DB:  siem_database.db`);
  console.log(`=======================================================`);
});
