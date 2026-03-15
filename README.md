# 🛡️ Enterprise SOC Lab — Security Operations Center

> A full-stack, real-world Security Operations Center simulation lab
> featuring AI-driven threat detection, MITRE ATT&CK mapping,
> incident response workflow, and a live dashboard.

---

## 🎯 Project Overview

This SOC Lab simulates a production-grade enterprise Security Operations Center.
It demonstrates real-world threat detection, alert triage, incident response,
and security monitoring — mapped to industry frameworks.

### Why This Project Stands Out
- ✅ **Real-world scenarios** — 8 attack types matching actual enterprise threats
- ✅ **MITRE ATT&CK mapping** — every alert tied to a technique ID
- ✅ **Incident response workflow** — assign, investigate, resolve alerts
- ✅ **Detection rules engine** — 8 rule-based detection policies
- ✅ **Live dashboard** — real-time alert feed with auto-refresh
- ✅ **Full documentation** — README, architecture, playbooks

---

## 🏗️ Architecture

```
soc-lab/
├── backend/
│   ├── threat_engine.py    ← Detection engine + alert generation
│   └── app.py              ← Flask REST API (optional)
├── frontend/
│   └── dashboard.html      ← Full SOC dashboard (standalone)
├── scripts/
│   └── simulate_attack.py  ← Attack simulation scripts
├── docs/
│   ├── architecture.md
│   ├── playbooks.md
│   └── mitre-mapping.md
├── requirements.txt
└── README.md
```

---

## ⚔️ Detected Attack Types

| Attack | MITRE ID | Tactic | Severity |
|---|---|---|---|
| **Brute Force** | T1110 | Credential Access | HIGH |
| **Port Scan** | T1046 | Discovery | MEDIUM |
| **DDoS Flood** | T1499 | Impact | CRITICAL |
| **Lateral Movement** | T1021 | Lateral Movement | HIGH |
| **Data Exfiltration** | T1041 | Exfiltration | CRITICAL |
| **C2 Beaconing** | T1071 | Command & Control | HIGH |
| **Privilege Escalation** | T1068 | Privilege Escalation | CRITICAL |
| **SQL Injection** | T1190 | Initial Access | HIGH |

---

## 🖥️ Dashboard Features

| Feature | Description |
|---|---|
| **Live Alert Feed** | Real-time alerts with auto-refresh every 30s |
| **Severity Dashboard** | Critical/High/Medium/Low breakdown with charts |
| **Alert Queue** | Filterable alert table with detail panel |
| **Incident Management** | Assign analysts, update status, add notes |
| **MITRE ATT&CK View** | Technique coverage map with detection counts |
| **Detection Rules** | All 8 active rules with conditions |
| **Event Timeline** | Chronological view of all events |
| **Attack Simulator** | Generate live alerts for any attack type |

---

## 🚀 Quick Start

### Option 1 — Standalone Dashboard (No Install Required!)
```bash
# Just open the dashboard in your browser
open frontend/dashboard.html
```

### Option 2 — Full Stack with Flask API
```bash
# Install dependencies
pip install -r requirements.txt

# Start the API
python backend/app.py
# → http://localhost:5001

# Open dashboard
open frontend/dashboard.html
```

---

## 🔍 Detection Rules

| Rule ID | Rule | Threshold | MITRE |
|---|---|---|---|
| RULE-001 | SSH Brute Force | > 10 fails in 60s | T1110 |
| RULE-002 | Port Scan | > 50 ports in 10s | T1046 |
| RULE-003 | DDoS Flood | > 10 Gbps sustained | T1499 |
| RULE-004 | Lateral Movement | > 5 SMB hosts in 10m | T1021 |
| RULE-005 | Data Exfiltration | > 10x outbound baseline | T1041 |
| RULE-006 | C2 Beacon | Periodic conn to C2 IP | T1071 |
| RULE-007 | Privilege Escalation | Sudo exploit pattern | T1068 |
| RULE-008 | SQL Injection | WAF SQL keyword match | T1190 |

---

## 📋 Incident Response Playbooks

### Brute Force Response (RULE-001)
```
1. Identify source IP → block at firewall
2. Check if any logins succeeded (auth.log)
3. Reset passwords for targeted accounts
4. Enable MFA on affected services
5. Add IP to threat intelligence blocklist
```

### Data Exfiltration Response (RULE-005)
```
1. Immediately block outbound connection
2. Isolate affected host from network
3. Capture forensic image of system
4. Identify data accessed / exfiltrated
5. Notify data protection officer (GDPR/compliance)
6. Preserve logs for investigation
```

### Lateral Movement Response (RULE-004)
```
1. Map all affected hosts
2. Reset all credentials on affected systems
3. Block SMB laterally between segments
4. Hunt for initial access vector
5. Deploy EDR on all endpoints
```

---

## 🗺️ MITRE ATT&CK Coverage

```
Initial Access     → T1190 (SQL Injection)
Credential Access  → T1110 (Brute Force)
Discovery          → T1046 (Port Scanning)
Lateral Movement   → T1021 (Remote Services)
Privilege Escalation → T1068 (Exploit Privesc)
Command & Control  → T1071 (App Layer Protocol)
Exfiltration       → T1041 (Over C2 Channel)
Impact             → T1499 (Endpoint DoS)
```

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| **Detection Engine** | Python 3.10+ |
| **API Backend** | Flask + Flask-CORS |
| **Dashboard** | Vanilla HTML/CSS/JS |
| **Database** | In-memory / SQLite |
| **Fonts** | Bebas Neue, Share Tech Mono, IBM Plex Sans |

---

## 📊 Skills Demonstrated

This project showcases skills directly relevant to SOC Analyst roles:

- **Threat Detection** — Rule-based and threshold detection
- **Alert Triage** — Severity classification and prioritization
- **MITRE ATT&CK** — Framework mapping and technique identification
- **Incident Response** — Alert lifecycle management
- **Log Analysis** — Raw log parsing and interpretation
- **Security Monitoring** — Real-time dashboards and metrics
- **Documentation** — Professional README and playbooks

---

## 🔮 Future Enhancements

- [ ] Wazuh SIEM integration for real log ingestion
- [ ] Suricata IDS rule integration
- [ ] ElasticSearch/OpenSearch for log storage
- [ ] Threat intelligence feeds (VirusTotal, AbuseIPDB)
- [ ] Email/Slack alerting integration
- [ ] Machine learning anomaly detection

---

## 📄 License

MIT License — Free for educational and portfolio use.

---

*Built as a SOC Analyst portfolio project.*
*Demonstrates real-world security operations workflows.*
