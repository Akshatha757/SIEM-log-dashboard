/* ==========================================================================
   SIEM LOG DASHBOARD - Data Store & Attack Scenarios
   ========================================================================== */

const SIEM_DATA = {
  // Analyst Profile Configuration (Editable in Settings)
  profile: {
    name: "Cybersecurity Analyst",
    initials: "CA",
    role: "Portfolio Security Developer",
    status: "Active Duty"
  },

  // System Metrics Initial State
  metrics: {
    totalEvents: 12458,
    activeAlerts: 24,
    threatsDetected: 8,
    criticalEvents: 3,
    threatLevel: 'ELEVATED' // LOW, NORMAL, ELEVATED, HIGH, CRITICAL
  },

  // Active Security Incidents Dataset
  incidents: [
    {
      id: "INC-2026-089",
      title: "Credential Spray & Lateral Movement Campaign",
      severity: "CRITICAL",
      status: "INVESTIGATING",
      targetHost: "DB-PROD-01 (10.0.2.10)",
      attackerIp: "192.168.1.50",
      assignedTo: "SOC Lead Analyst",
      timestamp: "Today 09:42",
      mitreTags: ["T1110 - Brute Force", "T1548.003 - Sudo Caching", "T1078 - Valid Accounts"],
      description: "Multi-vector adversary campaign targeting SSH service on DB-PROD-01 host followed by unauthorized sudo privilege escalation attempts.",
      playbookActions: ["Isolate Host Subnet", "Block Attacker IP on Firewall", "Revoke Active User Tokens"]
    },
    {
      id: "INC-2026-074",
      title: "High-Volume Data Exfiltration via Tor Exit Node",
      severity: "HIGH",
      status: "CONTAINED",
      targetHost: "WORKSTATION-FINANCE (10.0.1.88)",
      attackerIp: "185.220.101.4",
      assignedTo: "Network Forensics Team",
      timestamp: "Today 09:15",
      mitreTags: ["T1041 - Exfiltration Over C2 Channel", "T1071 - Application Layer Protocol"],
      description: "Compressed encrypted archive payload (4.2GB) transmitted out of corporate gateway to verified Tor exit node.",
      playbookActions: ["Block Attacker IP on Firewall", "Revoke Active User Tokens"]
    },
    {
      id: "INC-2026-061",
      title: "Web Application Password Spray Attack",
      severity: "MEDIUM",
      status: "CLOSED",
      targetHost: "WEB-APP-GATEWAY (10.0.1.5)",
      attackerIp: "172.16.0.42",
      assignedTo: "AppSec Response Team",
      timestamp: "Yesterday 16:30",
      mitreTags: ["T1110.003 - Password Spraying", "T1078 - Valid Accounts"],
      description: "Failed HTTP POST authentication burst across 12 employee accounts targeting /admin/login endpoint.",
      playbookActions: ["Rate Limit IP", "Force Password Reset"]
    }
  ],

  // Active Detection Rules Library
  rules: [
    {
      id: "RULE-SEC-4021",
      title: "SSH Brute Force Attack Threshold",
      author: "SOC Analyst",
      severity: "CRITICAL",
      logSource: "syslog.auth",
      status: "ACTIVE",
      threshold: 15,
      timeframe: "60s",
      mitre: "T1110.001 - Password Guessing",
      condition: "event == 'SSH_AUTH_FAIL' AND attempts >= 15",
      action: "Trigger Critical Alert & SOAR IP Containment",
      description: "Detects 15+ consecutive SSH authentication failures targeting a single server within 60 seconds."
    },
    {
      id: "RULE-PRIV-109",
      title: "Unauthorized Sudo Privilege Escalation",
      severity: "CRITICAL",
      author: "Threat Intel Team",
      logSource: "linux.secure",
      status: "ACTIVE",
      threshold: 1,
      timeframe: "Immediate",
      mitre: "T1548.003 - Sudo and Sudo Caching",
      condition: "event == 'SUDO_EXEC_DENIED' AND user != 'root'",
      action: "Trigger Critical Alert & User Session Lock",
      description: "Detects non-authorized service accounts attempting sudo execution without valid privileges."
    },
    {
      id: "RULE-EXFIL-302",
      title: "Suspicious Outbound Payload Volume",
      severity: "HIGH",
      author: "Network Security Team",
      logSource: "firewall.paloalto",
      status: "ACTIVE",
      threshold: 1000,
      timeframe: "300s",
      mitre: "T1041 - Exfiltration Over C2",
      condition: "bytesSent > 1073741824 AND destIp IN threat_intel_feed",
      action: "Trigger High Alert & Quarantine Connection",
      description: "Detects outbound data transfers exceeding 1GB to unverified external IP addresses or Tor exit nodes."
    },
    {
      id: "RULE-WEB-201",
      title: "Web App Authentication Spray",
      severity: "MEDIUM",
      author: "AppSec Analyst",
      logSource: "nginx.access",
      status: "ACTIVE",
      threshold: 10,
      timeframe: "120s",
      mitre: "T1078 - Valid Accounts",
      condition: "httpStatus == 401 AND endpoint == '/api/v1/auth/login'",
      action: "Trigger Medium Alert & Rate Limit IP",
      description: "Detects rapid HTTP 401 Unauthorized responses targeting authentication API endpoints."
    }
  ],

  // Security Overview Timeline answering the 5 SOC Questions
  timelineEvents: [
    {
      time: "09:35:12",
      title: "User Auth Requested",
      desc: "Single SSH login attempt for root from IP 192.168.1.50",
      severity: "INFO",
      socAnswers: {
        what: "Initial connection handshake from untrusted internal host.",
        threat: "Low immediate risk, single attempt.",
        severity: "INFO - Standard telemetry logging.",
        source: "192.168.1.50 (Host: WORKSTATION-DEV-04)",
        action: "Monitor for repeat authentication failures."
      }
    },
    {
      time: "09:38:45",
      title: "Multiple Failed Logins",
      desc: "14 consecutive failed SSH authentication attempts in 30 seconds",
      severity: "MEDIUM",
      socAnswers: {
        what: "Automated dictionary attack against local root account.",
        threat: "Suspicious behavior consistent with credential stuffing.",
        severity: "MEDIUM - Exceeds baseline threshold (3 failures/min).",
        source: "192.168.1.50 -> 10.0.4.15 (Auth Server)",
        action: "Trigger alert rule SEC-4021 and track IP connections."
      }
    },
    {
      time: "09:40:10",
      title: "Suspicious IP Correlation",
      desc: "Source IP matches known Indicators of Compromise (IOC-9912)",
      severity: "HIGH",
      socAnswers: {
        what: "Threat Intelligence feed matched source IP to malicious botnet node.",
        threat: "Confirmed adversary activity originating inside subnet.",
        severity: "HIGH - Active IOC match on internal network segment.",
        source: "Threat Intelligence Database (AlienVault / MISP feed)",
        action: "Prepare network firewall block rule."
      }
    },
    {
      time: "09:42:31",
      title: "Brute Force Attack Escalation",
      desc: "Threshold breached: 45 attempts/min. Privileged account targeted.",
      severity: "CRITICAL",
      socAnswers: {
        what: "Full-scale Brute Force Attack detected on core database server.",
        threat: "High probability of account compromise if unmitigated.",
        severity: "CRITICAL - High severity risk to mission-critical asset.",
        source: "192.168.1.50 (Attacker) targeting 10.0.2.10 (DB-PROD-01)",
        action: "Isolate IP on edge firewall and revoke active user sessions."
      }
    },
    {
      time: "09:44:00",
      title: "Automated Incident Containment",
      desc: "SOAR playbook triggered: IP isolated on firewall & analyst assigned.",
      severity: "INFO",
      socAnswers: {
        what: "Automated containment playbook executed successfully.",
        threat: "Threat neutralized. Attack vector blocked.",
        severity: "RESOLVED - Active mitigation active.",
        source: "Automated SOAR Engine",
        action: "Lead Analyst performing post-incident forensics."
      }
    }
  ],

  // Live Security Alerts
  alerts: [
    {
      id: "ALT-2026-901",
      title: "SSH Brute Force Attack Detected",
      severity: "CRITICAL",
      ruleId: "RULE-SEC-4021",
      sourceIp: "192.168.1.50",
      destIp: "10.0.2.10",
      attempts: 45,
      timestamp: "2 mins ago",
      status: "OPEN",
      description: "High volume of failed SSH login attempts targeting production DB server within a 60-second window."
    },
    {
      id: "ALT-2026-894",
      title: "Privilege Escalation via Sudo",
      severity: "CRITICAL",
      ruleId: "RULE-PRIV-109",
      sourceIp: "10.0.4.15",
      destIp: "10.0.4.15",
      attempts: 1,
      timestamp: "12 mins ago",
      status: "INVESTIGATING",
      description: "Non-standard user app-service attempted sudo execution of /bin/bash without valid ticket."
    },
    {
      id: "ALT-2026-882",
      title: "Unusual Outbound Data Transfer",
      severity: "HIGH",
      ruleId: "RULE-EXFIL-302",
      sourceIp: "10.0.1.88",
      destIp: "185.220.101.4",
      attempts: 3,
      timestamp: "28 mins ago",
      status: "OPEN",
      description: "Host transmitted 4.2 GB of encrypted compressed payload to unverified external Tor exit node."
    },
    {
      id: "ALT-2026-879",
      title: "Port Scan Activity (Nmap)",
      severity: "MEDIUM",
      ruleId: "RULE-NET-504",
      sourceIp: "192.168.1.25",
      destIp: "10.0.0.0/24",
      attempts: 1024,
      timestamp: "45 mins ago",
      status: "OPEN",
      description: "Sequential SYN scan detected across 1,024 TCP ports targeting internal server subnet."
    },
    {
      id: "ALT-2026-865",
      title: "Multiple Failed Web Admin Logins",
      severity: "MEDIUM",
      ruleId: "RULE-WEB-201",
      sourceIp: "172.16.0.42",
      destIp: "10.0.1.5",
      attempts: 12,
      timestamp: "1 hour ago",
      status: "RESOLVED",
      description: "Failed HTTP POST authentication on /admin/login endpoint with invalid CSRF tokens."
    },
    {
      id: "ALT-2026-850",
      title: "New Domain Admin User Created",
      severity: "HIGH",
      ruleId: "RULE-AD-809",
      sourceIp: "10.0.0.1",
      destIp: "10.0.0.1",
      attempts: 1,
      timestamp: "3 hours ago",
      status: "RESOLVED",
      description: "User account 'svc_temp_admin' added to Domain Administrators group outside maintenance hours."
    }
  ],

  // Live Logs Explorer Initial Dataset
  logs: [
    {
      id: "LOG-99201",
      timestamp: "2026-09-28 09:42:31",
      sourceIp: "192.168.1.50",
      destIp: "10.0.2.10",
      username: "root",
      event: "SSH_AUTH_FAIL",
      severity: "CRITICAL",
      message: "Failed password for root from 192.168.1.50 port 52310 ssh2",
      rule: "SEC-4021: SSH Brute Force Threshold",
      mitre: "T1110.001 - Password Guessing",
      payload: {
        protocol: "SSHv2",
        cipher: "chacha20-poly1305@openssh.com",
        failCount: 45,
        targetHost: "DB-PROD-01"
      }
    },
    {
      id: "LOG-99200",
      timestamp: "2026-09-28 09:41:18",
      sourceIp: "192.168.1.25",
      destIp: "10.0.4.15",
      username: "admin",
      event: "HTTP_401_UNAUTHORIZED",
      severity: "MEDIUM",
      message: "POST /api/v1/auth/login 401 Unauthorized (Invalid Credentials)",
      rule: "WEB-201: Web App Auth Failure",
      mitre: "T1078 - Valid Accounts",
      payload: {
        userAgent: "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0",
        endpoint: "/api/v1/auth/login",
        status: 401
      }
    },
    {
      id: "LOG-99199",
      timestamp: "2026-09-28 09:40:52",
      sourceIp: "192.168.1.10",
      destIp: "10.0.1.5",
      username: "j.doe",
      event: "USER_LOGIN_SUCCESS",
      severity: "INFO",
      message: "Successful Kerberos authentication for user j.doe@corp.local",
      rule: "AUDIT-101: Standard User Login",
      mitre: "T1078 - Valid Accounts",
      payload: {
        ticketType: "TGT",
        domainController: "DC-01.corp.local",
        workstation: "LAPTOP-JDOE"
      }
    },
    {
      id: "LOG-99198",
      timestamp: "2026-09-28 09:39:15",
      sourceIp: "10.0.1.88",
      destIp: "185.220.101.4",
      username: "system",
      event: "FIREWALL_OUTBOUND_CONN",
      severity: "HIGH",
      message: "Outbound TLS connection to suspicious external IP over port 443 (4.2GB)",
      rule: "EXFIL-302: Data Exfiltration Anomaly",
      mitre: "T1041 - Exfiltration Over C2 Channel",
      payload: {
        bytesSent: 4509715200,
        destinationCountry: "DE",
        threatFeedMatch: "Tor Exit Node List"
      }
    },
    {
      id: "LOG-99197",
      timestamp: "2026-09-28 09:35:01",
      sourceIp: "10.0.4.15",
      destIp: "10.0.4.15",
      username: "app-service",
      event: "SUDO_EXEC_DENIED",
      severity: "CRITICAL",
      message: "app-service : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash",
      rule: "PRIV-109: Unauthorized Sudo Attempt",
      mitre: "T1548.003 - Sudo and Sudo Caching",
      payload: {
        pid: 8841,
        tty: "pts/1",
        command: "/bin/bash"
      }
    },
    {
      id: "LOG-99196",
      timestamp: "2026-09-28 09:30:11",
      sourceIp: "192.168.1.100",
      destIp: "10.0.0.1",
      username: "m.smith",
      event: "VPN_CONNECT_SUCCESS",
      severity: "LOW",
      message: "WireGuard VPN tunnel established from 192.168.1.100 with MFA verification",
      rule: "NET-100: Remote VPN Access",
      mitre: "T1133 - External Remote Services",
      payload: {
        mfaProvider: "Duo Security",
        allocatedIp: "10.8.0.45"
      }
    }
  ],

  // Security Concepts Data for Interactive Modal/Drawer
  concepts: [
    {
      id: "siem",
      title: "SIEM",
      fullTitle: "Security Information & Event Management",
      icon: "shield-check",
      summary: "Centralized security software platform that collects, correlates, and analyzes log data across an enterprise.",
      whatIsIt: "SIEM combines Security Information Management (SIM) and Security Event Management (SEM) to deliver real-time analysis of security alerts generated by applications and network hardware.",
      whyImportant: "Without a SIEM, security teams would have to manually review thousands of log files scattered across hundreds of servers, firewalls, and applications, making it nearly impossible to spot stealthy attacks.",
      example: "When an attacker scans ports on Firewall A and 3 minutes later attempts password spraying on Server B, SIEM connects these isolated logs to reveal a coordinated attack.",
      howUsedHere: "This dashboard acts as the unified SOC interface, ingesting events, running correlation rules, displaying threat levels, and providing instant alert triage for analysts."
    },
    {
      id: "log-collection",
      title: "Log Collection",
      fullTitle: "Centralized Log Aggregation",
      icon: "database",
      summary: "The automated process of gathering raw event data from firewalls, servers, databases, and endpoints.",
      whatIsIt: "Log Collection uses agents (e.g., Syslog-ng, Fluentd, Elastic Agent) or agentless protocols (SNMP, WMI) to continuously stream log messages to a central repository.",
      whyImportant: "Ensures complete visibility across all digital assets and prevents attackers from deleting local logs on compromised machines to hide their footprints.",
      example: "Linux syslog transmitting `/var/log/auth.log` entries to the SIEM collector via encrypted TLS port 514.",
      howUsedHere: "The 'Live Logs' explorer and real-time feed demonstrate live ingested log telemetry categorized by severity and source device."
    },
    {
      id: "log-analysis",
      title: "Log Analysis",
      fullTitle: "Log Parsing & Normalization",
      icon: "cpu",
      summary: "Parsing unstructured raw text logs into standardized JSON key-value fields for instant searching.",
      whatIsIt: "Transforms messy syslog strings into structured data elements like `sourceIp`, `username`, `event_type`, and `timestamp`.",
      whyImportant: "Allows analysts to write precise queries like `severity == CRITICAL AND attempts > 10` across millions of logs in milliseconds.",
      example: "Parsing `Failed password for invalid user admin from 192.168.1.50` into `{ event: 'AUTH_FAIL', user: 'admin', ip: '192.168.1.50' }`.",
      howUsedHere: "In the Log Explorer, clicking any row reveals normalized key-value fields and MITRE ATT&CK taxonomy tags."
    },
    {
      id: "event-correlation",
      title: "Event Correlation",
      fullTitle: "Cross-Device Pattern Detection",
      icon: "git-merge",
      summary: "Linking multiple related events across different systems to identify complex attack chains.",
      whatIsIt: "Correlation engines evaluate rules over sliding time windows to detect complex behaviors that single logs cannot expose.",
      whyImportant: "Separates benign single failures from sophisticated multi-stage attacks like APTs (Advanced Persistent Threats).",
      example: "If Event A (Failed Login) occurs 10 times in 1 min AND Event B (Privilege Escalation) follows on the same host within 5 mins → Trigger CRITICAL Alert.",
      howUsedHere: "The 'Security Timeline' component visually demonstrates how 5 discrete logs correlate into a single Brute Force Incident."
    },
    {
      id: "threat-detection",
      title: "Threat Detection",
      fullTitle: "Signature & Anomaly-Based Analytics",
      icon: "radar",
      summary: "Identifying malicious behavior using predefined rule signatures and behavioral anomaly baselines.",
      whatIsIt: "Combines rule-based matching (e.g., YARA/Sigma rules) with statistical heuristics (e.g., unusual data volume spikes).",
      whyImportant: "Enables proactive threat hunting before data exfiltration or ransomware encryption takes place.",
      example: "Detecting an internal workstation connecting to a known C2 (Command & Control) server IP address.",
      howUsedHere: "The 'Threat Pulse' gauge dynamically recalculates the SOC risk posture based on active detection rules."
    },
    {
      id: "ioc",
      title: "Indicators of Compromise (IOC)",
      fullTitle: "Forensic Attack Artifacts",
      icon: "activity",
      summary: "Digital evidence (IP addresses, file hashes, domain names) suggesting a security breach.",
      whatIsIt: "Standardized telemetry signatures shared via Threat Intelligence feeds (STIX/TAXII, MISP) to identify known threat actors.",
      whyImportant: "Allows immediate detection of globally recognized malware strains and attacker infrastructure.",
      example: "Matching an uploaded payload's SHA-256 hash `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` against VirusTotal.",
      howUsedHere: "Alert details highlight matched IOCs like malicious IP addresses or Tor exit nodes."
    },
    {
      id: "alerting",
      title: "Alerting & Triage",
      fullTitle: "SOC Alert Management",
      icon: "bell",
      summary: "Notifying security analysts of high-priority security incidents and managing resolution workflows.",
      whatIsIt: "Filtering noise so analysts focus on high-fidelity alerts requiring human intervention.",
      whyImportant: "Prevents 'Alert Fatigue', a major cause of missed breaches when analysts are overwhelmed by false positives.",
      example: "Routing CRITICAL alerts to PagerDuty or Slack while automatically suppressing routine false-positive backup jobs.",
      howUsedHere: "The 'Alert Management' page provides interactive cards with `[Investigate]`, `[Resolve]`, and `[Suppress]` buttons."
    },
    {
      id: "incident-response",
      title: "Incident Response",
      fullTitle: "Containment & Remediation (SOAR)",
      icon: "zap",
      summary: "Structured actions taken to contain, eradicate, and recover from a security breach.",
      whatIsIt: "Executing automated playbooks (SOAR) to block firewall ports, isolate infected hosts, or disable compromised user credentials.",
      whyImportant: "Dramatically reduces Mean Time to Respond (MTTR) from hours to seconds.",
      example: "Automatically pushing a TCP block rule to Palo Alto Firewall when a host exceeds exfiltration thresholds.",
      howUsedHere: "Analyst actions in the dashboard trigger simulated firewall isolates and session revocations."
    }
  ],

  // System Health Status Data
  systemStatus: {
    overallStatus: "Operational",
    components: [
      { name: "Log Collector (Syslog/TLS)", status: "Online", latency: "1.2ms", eps: "4,250 EPS", health: 100 },
      { name: "Detection Rule Engine", status: "Online", latency: "0.4ms", eps: "Rules Active: 142", health: 100 },
      { name: "Elastic Log Storage Cluster", status: "Online", latency: "8.5ms", eps: "Storage: 42% Used", health: 98 },
      { name: "Alert & Notification Engine", status: "Online", latency: "0.1ms", eps: "Queue: 0", health: 100 },
      { name: "Threat Intelligence Feed (MISP)", status: "Synced", latency: "12m ago", eps: "148,900 IOCs", health: 100 }
    ]
  },

  // Interactive Attack Simulation Presets
  attackScenarios: {
    bruteForce: {
      name: "Brute Force Attack Simulation",
      threatLevel: "CRITICAL",
      addAlert: {
        id: "ALT-SIM-99",
        title: "CRITICAL: Active Password Spray Attack",
        severity: "CRITICAL",
        ruleId: "RULE-SEC-4021",
        sourceIp: "45.142.214.10",
        destIp: "10.0.0.5",
        attempts: 180,
        timestamp: "Just now",
        status: "OPEN",
        description: "Massive SSH dictionary attack detected targeting administrative domain accounts."
      },
      addLog: {
        id: "LOG-SIM-99",
        timestamp: "Just now",
        sourceIp: "45.142.214.10",
        destIp: "10.0.0.5",
        username: "admin_root",
        event: "SSH_BRUTE_FORCE_BURST",
        severity: "CRITICAL",
        message: "ALERT: 180 failed auth attempts in 10 sec from external botnet IP 45.142.214.10",
        rule: "SEC-4021: SSH Brute Force Pattern",
        mitre: "T1110.003 - Password Spraying"
      }
    },
    ransomware: {
      name: "Ransomware Lateral Movement",
      threatLevel: "HIGH",
      addAlert: {
        id: "ALT-SIM-88",
        title: "HIGH: Mass File Extension Modification (.locked)",
        severity: "HIGH",
        ruleId: "RULE-RANSOM-901",
        sourceIp: "10.0.2.88",
        destIp: "10.0.2.0/24",
        attempts: 450,
        timestamp: "Just now",
        status: "OPEN",
        description: "High velocity file rename operations detected on SMB shared network drive."
      },
      addLog: {
        id: "LOG-SIM-88",
        timestamp: "Just now",
        sourceIp: "10.0.2.88",
        destIp: "10.0.2.1",
        username: "finance_user",
        event: "SMB_FILE_MASS_RENAME",
        severity: "HIGH",
        message: "Process vssadmin.exe attempted shadow copy deletion on host WORKSTATION-FINANCE",
        rule: "RANSOM-901: Ransomware Heuristic Pattern",
        mitre: "T1490 - Inhibit System Recovery"
      }
    },
    portScan: {
      name: "Reconnaissance Port Scan",
      threatLevel: "MEDIUM",
      addAlert: {
        id: "ALT-SIM-77",
        title: "MEDIUM: Subnet Reconnaissance SYN Scan",
        severity: "MEDIUM",
        ruleId: "RULE-SCAN-301",
        sourceIp: "192.168.1.199",
        destIp: "10.0.0.0/16",
        attempts: 4096,
        timestamp: "Just now",
        status: "OPEN",
        description: "Rapid TCP SYN probe detected across web application ports 80, 443, 8080."
      },
      addLog: {
        id: "LOG-SIM-77",
        timestamp: "Just now",
        sourceIp: "192.168.1.199",
        destIp: "10.0.0.12",
        username: "anonymous",
        event: "PORT_SCAN_SYN_BURST",
        severity: "MEDIUM",
        message: "Nmap SYN scan probe received on port 8080 from internal host 192.168.1.199",
        rule: "SCAN-301: Network Probe Detection",
        mitre: "T1046 - Network Service Discovery"
      }
    }
  }
};
