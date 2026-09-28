# 🛡️ SIEM Log Dashboard & SOC Operations Console

## 📌 Project Definition
The **SIEM Log Dashboard** is a full-stack Security Information and Event Management (SIEM) application designed to simulate a real-world Security Operations Center (SOC) environment. It aggregates security event telemetry, normalizes raw syslog data, categorizes threat severities, visualizes network attack topology, compiles SIGMA detection rules, and executes automated SOAR containment playbooks using a Node.js Express REST API backend connected to a persistent SQLite database.

---

## 🏗️ 1. Complete System Architecture & Technical Design

### 📦 A. High-Level Component Architecture (Box Diagram)

```text
┌───────────────────────────────────────────────────────────────────────────────────┐
│                                FRONTEND LAYER (Client)                             │
│                                                                                   │
│  ┌───────────────────────────┐  ┌────────────────────────┐  ┌──────────────────┐ │
│  │ Single Page App Layout    │  │ Glassmorphic CSS Engine│  │ SVG Attack Map   │ │
│  │ (index.html)              │  │ (css/styles.css)       │  │(js/network-map.js│ │
│  └─────────────┬─────────────┘  └───────────┬────────────┘  └────────┬─────────┘ │
│                │                            │                        │            │
│                └────────────────────────────┼────────────────────────┘            │
│                                             ▼                                     │
│  ┌──────────────────────────────────────────────────────────────────────────────┐ │
│  │                     SiemApplication Controller (js/app.js)                  │ │
│  │   • View Navigation System      • Severity Filter Engine (CRITICAL..INFO)    │ │
│  │   • Live Telemetry Stream       • Modal Investigation & SOAR Controller      │ │
│  │   • HTML5 Canvas Engine (charts.js) • Local In-Memory Data Store (data.js)    │ │
│  └──────────────────────────────────────┬───────────────────────────────────────┘ │
└─────────────────────────────────────────┼─────────────────────────────────────────┘
                                          │
                                          │ HTTP REST API Requests (JSON)
                                          │ (fetch http://localhost:5000/api)
                                          ▼
┌───────────────────────────────────────────────────────────────────────────────────┐
│                                BACKEND LAYER (Server)                             │
│                                                                                   │
│  ┌──────────────────────────────────────────────────────────────────────────────┐ │
│  │                   Node.js + Express REST API (server.js)                     │ │
│  │   • CORS & Static Middleware     • Attack Simulator Engine (/simulate)       │ │
│  │   • Alerts API (/api/alerts)     • Security Logs API (/api/logs)             │ │
│  │   • Detection Rules API (/rules) • Analyst Profile API (/api/profile)        │ │
│  └──────────────────────────────────────┬───────────────────────────────────────┘ │
└─────────────────────────────────────────┼─────────────────────────────────────────┘
                                          │
                                          │ SQL Queries (INSERT / SELECT / UPDATE)
                                          ▼
┌───────────────────────────────────────────────────────────────────────────────────┐
│                              PERSISTENCE LAYER (Database)                         │
│                                                                                   │
│  ┌──────────────────────────────────────────────────────────────────────────────┐ │
│  │                     siem_database.db (SQLite 3 Database)                     │ │
│  │   ┌──────────────┐  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐   │ │
│  │   │ profile DB   │  │ metrics DB  │  │ logs DB      │  │ alerts DB        │   │ │
│  │   └──────────────┘  └─────────────┘  └──────────────┘  └──────────────────┘   │ │
│  │   ┌──────────────┐  ┌─────────────┐                                           │ │
│  │   │ rules DB     │  │incidents DB │                                           │ │
│  │   └──────────────┘  └─────────────┘                                           │ │
│  └──────────────────────────────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────────────────────────┘
```

---

### 🔄 B. Telemetry & Alert Triage Data Flow (Pipeline Box Diagram)

```text
  [ Incoming Syslog Stream / Attack Simulator ]
                       │
                       ▼
    1. HTTP POST Request ───►  Express REST API (/api/simulate)
                                       │
                                       ▼
    2. Database Persist  ───►  SQLite3 DB (siem_database.db)
                               (INSERT alert, INSERT log, UPDATE metrics)
                                       │
                                       ▼
    3. Client Ingestion  ───►  Frontend fetch() ──► update this.data.alerts
                                       │
                                       ▼
    4. DOM Render Grid   ───►  renderAlerts('CRITICAL')
                               (Generates Severity Cards & Filter Pills)
                                       │
                                       ▼
    5. Analyst Triage    ───►  Click "🔍 Investigate"
                                       │
                                       ▼
    6. Modal Triage Box  ───►  openModal() Popup Window
                               (Displays Attacker IP, Asset, Rule & Block Action)
                                       │
                                       ▼
    7. SOAR Execution    ───►  Click "🔒 Block IP on Firewall"
                               (Triggers Automated Containment Toast Action)
```

---

### 🌐 C. SVG Network Attack Topology Architecture (Box Diagram)

```text
 ┌──────────────────────┐             ┌──────────────────────┐
 │ Untrusted Dev Host   │             │ Corporate Gateway    │
 │  (192.168.1.50)      │ ──[SSH]───► │  PaloAlto Firewall   │
 └──────────────────────┘             └──────────┬───────────┘
                                                 │
                                                 ▼
 ┌──────────────────────┐             ┌──────────────────────┐
 │ Threat Intel Engine  │ ◄──[IOC]─── │ Ingestion SIEM Server│
 │ (AlienVault Feed)    │             │  (10.0.0.1 Engine)   │
 └──────────────────────┘             └──────────┬───────────┘
                                                 │
                                                 ▼
                                      ┌──────────────────────┐
                                      │ Production DB Server │
                                      │  (DB-PROD-01 Target) │
                                      └──────────────────────┘
```

---

## 🗄️ 2. Database Schema Architecture (SQLite Relational Model)

The persistent database `siem_database.db` contains 6 relational tables:

| Table Name | Primary Key | Key Columns | Purpose |
| :--- | :--- | :--- | :--- |
| **`profile`** | `id` (INTEGER) | `name`, `initials`, `role`, `status` | Analyst Portfolio Profile customization. |
| **`metrics`** | `id` (INTEGER) | `total_events`, `active_alerts`, `threats_detected`, `critical_events`, `threat_level` | System counters and global threat posture level. |
| **`logs`** | `id` (TEXT) | `timestamp`, `source_ip`, `dest_ip`, `username`, `event`, `severity`, `message`, `rule`, `mitre`, `payload` | Ingested syslog stream with raw syslog & JSON payload. |
| **`alerts`** | `id` (TEXT) | `title`, `severity`, `rule_id`, `source_ip`, `dest_ip`, `attempts`, `timestamp`, `status`, `description` | Triage alert queue for SOC investigation. |
| **`rules`** | `id` (TEXT) | `title`, `author`, `severity`, `log_source`, `status`, `threshold`, `timeframe`, `mitre`, `condition`, `action`, `description` | SIGMA detection rules library. |
| **`incidents`** | `id` (TEXT) | `title`, `severity`, `status`, `target_host`, `attacker_ip`, `assigned_to`, `timestamp`, `mitre_tags`, `description`, `playbook_actions` | Correlated security campaigns and SOAR playbooks. |

---

## 🌟 3. Key Features & Capabilities

### 🎨 A. Modern SOC Interface & Design Language
* **HSL Color System**: Soft dark navy canvas (`#060911`), electric blue accents (`#3b82f6`), soft cyan highlights (`#06b6d4`), and purple glow (`#a855f7`).
* **Strict Severity Palette**:
  * 🟦 **INFO** — Standard telemetry events
  * 🟩 **LOW** — Low severity operational logs
  * 🟨 **MEDIUM** — Suspicious anomalies requiring analyst review
  * 🟧 **HIGH** — High priority security alerts
  * 🟥 **CRITICAL** — Urgent threats requiring immediate containment

### 📊 B. Telemetry & Visual Analytics
* **Security Activity Curve Chart**: HTML5 Canvas rendering bezier curves for event ingestion vs security alerts.
* **Threat Activity Radar**: Rotating radar sweep visualizing threat categories.
* **Threat Pulse Gauge**: Interactive threat level indicator (LOW ➔ NORMAL ➔ ELEVATED ➔ HIGH ➔ CRITICAL).

### 🚨 C. Alert Triage & SOAR Playbooks
* Filter alert grid by `ALL`, `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO`.
* **Investigation Modal**: Click **🔍 Investigate** to pop up a focused triage modal displaying Target Host, Attacker IP, Rule ID, and Attempt Count.
* **Containment Buttons**: Click **🔒 Block IP on Firewall**, **🚫 Revoke Credentials**, or **🛡️ Isolate Subnet**.

### 🧠 D. SOC Analyst 5-Question Framework
Answers the core questions required during security triage:
1. **What is happening?** *(Brute force SSH spray)*
2. **Is there a threat?** *(Yes, active adversary attack)*
3. **How serious is it?** *(CRITICAL - targeting production database)*
4. **Where did it come from?** *(192.168.1.50 - Untrusted Workstation)*
5. **What should be investigated?** *(Block IP & revoke credentials)*

### 📝 E. Custom SIGMA Detection Rule Compiler
* Author custom detection rules with threshold and timeframe parameters.
* Test against incoming log streams in the **Rule Sandbox**.
* Compile signatures into standardized **SIGMA/YARA YAML** output with **MITRE ATT&CK®** mapping tags.

### 🔍 F. Ingested Log Explorer
* Browse normalized security events with timestamp, source/destination IP, and event type.
* Click any log row to expand **raw Syslog messages** and **JSON payloads**.

---

## 📁 4. Project Directory Structure

```text
SIEM log dashboard/
│
├── index.html              # Single Page Application (SPA) HTML5 layout
├── server.js               # Node.js Express REST API server & SQLite database controller
├── package.json            # Project dependencies & scripts (Express, Cors, SQLite3)
├── siem_database.db        # SQLite database storing persistent logs, alerts & rules
├── README.md               # Main project documentation & architecture guide
├── STUDENT_GUIDE.md        # Comprehensive student viva & interview explanation guide
│
├── css/
│   └── styles.css          # Glassmorphism design system, severity tokens & modal popups
│
└── js/
    ├── app.js              # Central application controller, REST API fetch & modal engine
    ├── data.js             # Telemetry datasets, active alerts, rules & attack scenarios
    ├── charts.js           # HTML5 Canvas chart engine (Activity curve & Threat radar)
    └── network-map.js      # SVG Attack Topology map renderer
```

---

## ⚡ 5. Step-by-Step Setup & Run Instructions

### Step 1: Open Terminal in Project Directory
```bash
cd "d:\SIEM log dashboard"
```

### Step 2: Install Node.js Dependencies
```bash
npm install
```

### Step 3: Start the Backend REST API Server
```bash
node server.js
```
*Console output:*
```text
=======================================================
🛡️  SIEM Log Dashboard Node.js REST API Server Running
🌐 Server URL: http://localhost:5000
💾 SQLite DB:  siem_database.db
=======================================================
Connected to SQLite database: siem_database.db
```

### Step 4: Serve Frontend Application
In a second terminal window:
```bash
python -m http.server 8080
```

### Step 5: Open Browser
Navigate to:
```text
http://localhost:8080/
```
Verify the header status pill displays: `🟢 EXPRESS & SQLITE BACKEND ACTIVE (PORT 5000)`.

---

## 📡 6. REST API Endpoint Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/metrics` | Returns total event count, active alerts, threat count, and current threat posture level. |
| `GET` | `/api/alerts` | Fetches all active alerts stored in SQLite database. |
| `POST`| `/api/alerts/:id/resolve` | Marks an alert status as `RESOLVED` in SQLite DB. |
| `GET` | `/api/logs` | Retrieves normalized security event logs (supports `?severity=CRITICAL`). |
| `GET` | `/api/rules` | Fetches active detection rules library. |
| `POST`| `/api/rules` | Persists a new custom SIGMA rule to SQLite DB. |
| `GET` | `/api/incidents` | Fetches incident campaigns and SOAR playbook actions. |
| `GET` | `/api/profile` | Fetches analyst profile details. |
| `POST`| `/api/profile` | Updates analyst profile name and title in SQLite DB. |
| `POST`| `/api/simulate` | Triggers attack scenarios (`bruteForce`, `ransomware`, `reset`). |

---

## 📝 Summary

The SIEM Log Dashboard is a full-stack cybersecurity application providing real-time log ingestion, alert triage, network attack topology visualizer, custom SIGMA rule compilation, and SOAR containment workflows powered by a Node.js Express REST API backend and persistent SQLite database.
