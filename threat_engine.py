"""
threat_engine.py
────────────────
SOC Lab — Real-World Threat Detection Engine
Simulates enterprise-grade detection logic for:
  • Brute Force Attacks
  • Port Scanning / Reconnaissance
  • DDoS / Flood Attacks
  • Privilege Escalation
  • Lateral Movement
  • Data Exfiltration
  • Malware Beaconing
Maps every detection to MITRE ATT&CK framework.
"""

import random
import hashlib
import ipaddress
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from dataclasses import dataclass, field, asdict
from collections import defaultdict
import json


# ══════════════════════════════════════════════════════
#  ENUMS & CONSTANTS
# ══════════════════════════════════════════════════════

SEVERITY_LEVELS = {
    "CRITICAL": 5,
    "HIGH":     4,
    "MEDIUM":   3,
    "LOW":      2,
    "INFO":     1,
}

MITRE_TECHNIQUES = {
    "brute_force":          {"id": "T1110",   "tactic": "Credential Access",   "name": "Brute Force"},
    "port_scan":            {"id": "T1046",   "tactic": "Discovery",           "name": "Network Service Discovery"},
    "ddos":                 {"id": "T1499",   "tactic": "Impact",              "name": "Endpoint Denial of Service"},
    "privilege_escalation": {"id": "T1068",   "tactic": "Privilege Escalation","name": "Exploitation for Privilege Escalation"},
    "lateral_movement":     {"id": "T1021",   "tactic": "Lateral Movement",    "name": "Remote Services"},
    "data_exfiltration":    {"id": "T1041",   "tactic": "Exfiltration",        "name": "Exfiltration Over C2 Channel"},
    "malware_beacon":       {"id": "T1071",   "tactic": "Command & Control",   "name": "Application Layer Protocol"},
    "phishing":             {"id": "T1566",   "tactic": "Initial Access",      "name": "Phishing"},
    "sql_injection":        {"id": "T1190",   "tactic": "Initial Access",      "name": "Exploit Public-Facing Application"},
    "ransomware":           {"id": "T1486",   "tactic": "Impact",              "name": "Data Encrypted for Impact"},
}

ATTACK_SOURCES = [
    "185.220.101.45", "45.142.212.100", "194.165.16.77",
    "103.251.167.20", "91.240.118.172", "62.233.50.11",
    "198.98.56.143",  "185.156.73.54",  "77.247.110.21",
    "51.77.135.89",   "185.220.103.5",  "192.42.116.16",
]

INTERNAL_HOSTS = [
    "192.168.1.10",  "192.168.1.20",  "192.168.1.30",
    "192.168.1.50",  "192.168.1.100", "10.0.0.15",
    "10.0.0.25",     "10.0.0.40",     "172.16.0.5",
]

USERNAMES = [
    "admin", "root", "administrator", "sysadmin",
    "john.doe", "jane.smith", "dbuser", "service_account",
    "backup_user", "guest", "operator",
]

SERVICES = ["SSH", "RDP", "FTP", "HTTP", "HTTPS", "SMB", "LDAP", "MySQL", "Telnet"]
PROTOCOLS = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS", "SMTP"]


# ══════════════════════════════════════════════════════
#  DATA MODELS
# ══════════════════════════════════════════════════════

@dataclass
class Alert:
    """Represents a SOC security alert"""
    alert_id:       str
    timestamp:      str
    severity:       str
    alert_type:     str
    title:          str
    description:    str
    source_ip:      str
    dest_ip:        str
    dest_port:      int
    protocol:       str
    mitre_id:       str
    mitre_tactic:   str
    mitre_name:     str
    status:         str = "open"
    assigned_to:    str = ""
    resolution:     str = ""
    raw_log:        str = ""
    tags:           List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class NetworkEvent:
    """Represents a raw network event/log entry"""
    timestamp:   str
    source_ip:   str
    dest_ip:     str
    dest_port:   int
    protocol:    str
    bytes_sent:  int
    status:      str
    service:     str
    username:    str = ""
    action:      str = "allow"


# ══════════════════════════════════════════════════════
#  ALERT GENERATOR
# ══════════════════════════════════════════════════════

class AlertGenerator:
    """Generates realistic simulated security alerts"""

    def __init__(self):
        self._counter = 0

    def _new_id(self) -> str:
        self._counter += 1
        return f"ALT-{datetime.now().strftime('%Y%m%d')}-{self._counter:04d}"

    def _ts(self, minutes_ago: int = 0) -> str:
        t = datetime.now() - timedelta(minutes=minutes_ago)
        return t.strftime("%Y-%m-%d %H:%M:%S")

    def _rand_internal(self) -> str:
        return random.choice(INTERNAL_HOSTS)

    def _rand_external(self) -> str:
        return random.choice(ATTACK_SOURCES)

    # ── Individual attack generators ──────────────────

    def brute_force_alert(self, minutes_ago: int = 0) -> Alert:
        attempts  = random.randint(50, 500)
        service   = random.choice(["SSH", "RDP", "FTP"])
        port_map  = {"SSH": 22, "RDP": 3389, "FTP": 21}
        username  = random.choice(USERNAMES)
        src       = self._rand_external()
        dst       = self._rand_internal()
        m         = MITRE_TECHNIQUES["brute_force"]

        return Alert(
            alert_id     = self._new_id(),
            timestamp    = self._ts(minutes_ago),
            severity     = "HIGH",
            alert_type   = "brute_force",
            title        = f"Brute Force Attack Detected on {service}",
            description  = (
                f"{attempts} failed login attempts for user '{username}' "
                f"on {service} from {src} in the last 5 minutes. "
                f"Threshold exceeded: 10 attempts/min."
            ),
            source_ip    = src,
            dest_ip      = dst,
            dest_port    = port_map[service],
            protocol     = "TCP",
            mitre_id     = m["id"],
            mitre_tactic = m["tactic"],
            mitre_name   = m["name"],
            tags         = ["brute-force", service.lower(), "credential-attack"],
            raw_log      = (
                f'[{self._ts(minutes_ago)}] FAIL sshd[1234]: '
                f'Failed password for {username} from {src} port 54321 ssh2'
            ),
        )

    def port_scan_alert(self, minutes_ago: int = 0) -> Alert:
        ports_scanned = random.randint(100, 65535)
        src    = self._rand_external()
        dst    = self._rand_internal()
        m      = MITRE_TECHNIQUES["port_scan"]

        return Alert(
            alert_id     = self._new_id(),
            timestamp    = self._ts(minutes_ago),
            severity     = "MEDIUM",
            alert_type   = "port_scan",
            title        = "Port Scan / Reconnaissance Detected",
            description  = (
                f"Host {src} scanned {ports_scanned} ports on {dst} "
                f"within 60 seconds. SYN scan pattern identified. "
                f"Possible Nmap or Masscan activity."
            ),
            source_ip    = src,
            dest_ip      = dst,
            dest_port    = 0,
            protocol     = "TCP",
            mitre_id     = m["id"],
            mitre_tactic = m["tactic"],
            mitre_name   = m["name"],
            tags         = ["reconnaissance", "port-scan", "nmap"],
            raw_log      = (
                f'[{self._ts(minutes_ago)}] ALERT suricata: '
                f'ET SCAN Nmap Scripting Engine User-Agent Detected '
                f'{src}:{random.randint(1024,65535)} -> {dst}:80'
            ),
        )

    def ddos_alert(self, minutes_ago: int = 0) -> Alert:
        pps    = random.randint(50000, 500000)
        gbps   = round(random.uniform(0.5, 10.0), 2)
        src    = self._rand_external()
        dst    = self._rand_internal()
        m      = MITRE_TECHNIQUES["ddos"]

        return Alert(
            alert_id     = self._new_id(),
            timestamp    = self._ts(minutes_ago),
            severity     = "CRITICAL",
            alert_type   = "ddos",
            title        = "DDoS Attack — Traffic Flood Detected",
            description  = (
                f"Abnormal traffic spike: {pps:,} packets/sec ({gbps} Gbps) "
                f"targeting {dst}. Multiple source IPs detected — "
                f"volumetric DDoS attack in progress. "
                f"Automatic rate limiting engaged."
            ),
            source_ip    = src,
            dest_ip      = dst,
            dest_port    = random.choice([80, 443, 53]),
            protocol     = random.choice(["UDP", "TCP", "ICMP"]),
            mitre_id     = m["id"],
            mitre_tactic = m["tactic"],
            mitre_name   = m["name"],
            tags         = ["ddos", "flood", "availability", "critical"],
            raw_log      = (
                f'[{self._ts(minutes_ago)}] CRITICAL snort: '
                f'DOS Attack detected: {pps} pps from {src}'
            ),
        )

    def lateral_movement_alert(self, minutes_ago: int = 0) -> Alert:
        src    = self._rand_internal()
        dst    = self._rand_internal()
        while dst == src:
            dst = self._rand_internal()
        user   = random.choice(USERNAMES)
        m      = MITRE_TECHNIQUES["lateral_movement"]

        return Alert(
            alert_id     = self._new_id(),
            timestamp    = self._ts(minutes_ago),
            severity     = "HIGH",
            alert_type   = "lateral_movement",
            title        = "Lateral Movement — Suspicious Internal SMB Activity",
            description  = (
                f"User '{user}' accessed {dst} from {src} via SMB. "
                f"Unusual lateral movement pattern detected. "
                f"Host {src} has accessed 6 internal hosts in 10 minutes. "
                f"Possible pass-the-hash or worm propagation."
            ),
            source_ip    = src,
            dest_ip      = dst,
            dest_port    = 445,
            protocol     = "TCP",
            mitre_id     = m["id"],
            mitre_tactic = m["tactic"],
            mitre_name   = m["name"],
            tags         = ["lateral-movement", "smb", "internal", "pass-the-hash"],
            raw_log      = (
                f'[{self._ts(minutes_ago)}] WARN wazuh: '
                f'SMB access: {src} -> {dst}:445 user={user} '
                f'share=C$ action=CONNECT'
            ),
        )

    def data_exfiltration_alert(self, minutes_ago: int = 0) -> Alert:
        mb     = random.randint(500, 5000)
        src    = self._rand_internal()
        dst    = self._rand_external()
        m      = MITRE_TECHNIQUES["data_exfiltration"]

        return Alert(
            alert_id     = self._new_id(),
            timestamp    = self._ts(minutes_ago),
            severity     = "CRITICAL",
            alert_type   = "data_exfiltration",
            title        = "Potential Data Exfiltration Detected",
            description  = (
                f"Host {src} transferred {mb} MB of data to external IP {dst} "
                f"over HTTPS. Unusual outbound data volume — "
                f"10x above baseline. Possible data exfiltration via "
                f"encrypted channel."
            ),
            source_ip    = src,
            dest_ip      = dst,
            dest_port    = 443,
            protocol     = "HTTPS",
            mitre_id     = m["id"],
            mitre_tactic = m["tactic"],
            mitre_name   = m["name"],
            tags         = ["exfiltration", "data-loss", "https", "critical"],
            raw_log      = (
                f'[{self._ts(minutes_ago)}] ALERT zeek: '
                f'conn {src} -> {dst}:443 '
                f'bytes={mb*1024*1024} duration=300s'
            ),
        )

    def malware_beacon_alert(self, minutes_ago: int = 0) -> Alert:
        interval = random.choice([30, 60, 120, 300])
        src      = self._rand_internal()
        dst      = self._rand_external()
        m        = MITRE_TECHNIQUES["malware_beacon"]

        return Alert(
            alert_id     = self._new_id(),
            timestamp    = self._ts(minutes_ago),
            severity     = "HIGH",
            alert_type   = "malware_beacon",
            title        = "C2 Beaconing Behavior Detected",
            description  = (
                f"Host {src} making periodic connections to {dst} "
                f"every {interval} seconds. Consistent beaconing pattern "
                f"indicates possible C2 malware communication. "
                f"Domain flagged in threat intelligence feeds."
            ),
            source_ip    = src,
            dest_ip      = dst,
            dest_port    = random.choice([80, 443, 8080, 8443]),
            protocol     = "HTTP",
            mitre_id     = m["id"],
            mitre_tactic = m["tactic"],
            mitre_name   = m["name"],
            tags         = ["c2", "malware", "beacon", "threat-intel"],
            raw_log      = (
                f'[{self._ts(minutes_ago)}] ALERT suricata: '
                f'ET C2 Known Botnet C2 Domain in DNS Lookup '
                f'src={src} dst={dst}'
            ),
        )

    def privilege_escalation_alert(self, minutes_ago: int = 0) -> Alert:
        user   = random.choice(USERNAMES)
        host   = self._rand_internal()
        m      = MITRE_TECHNIQUES["privilege_escalation"]

        return Alert(
            alert_id     = self._new_id(),
            timestamp    = self._ts(minutes_ago),
            severity     = "CRITICAL",
            alert_type   = "privilege_escalation",
            title        = "Privilege Escalation Attempt Detected",
            description  = (
                f"User '{user}' on {host} attempted privilege escalation "
                f"via sudo exploit. Suspicious command: 'sudo -l' followed by "
                f"known CVE-2023-22809 exploitation attempt. "
                f"Root access may have been obtained."
            ),
            source_ip    = host,
            dest_ip      = host,
            dest_port    = 0,
            protocol     = "N/A",
            mitre_id     = m["id"],
            mitre_tactic = m["tactic"],
            mitre_name   = m["name"],
            tags         = ["privilege-escalation", "sudo", "linux", "cve"],
            raw_log      = (
                f'[{self._ts(minutes_ago)}] CRITICAL auditd: '
                f'type=SYSCALL arch=x86_64 syscall=execve '
                f'uid={random.randint(1000,9999)} user={user} '
                f'cmd=sudo exploit'
            ),
        )

    def sql_injection_alert(self, minutes_ago: int = 0) -> Alert:
        src    = self._rand_external()
        dst    = self._rand_internal()
        m      = MITRE_TECHNIQUES["sql_injection"]

        return Alert(
            alert_id     = self._new_id(),
            timestamp    = self._ts(minutes_ago),
            severity     = "HIGH",
            alert_type   = "sql_injection",
            title        = "SQL Injection Attack Detected",
            description  = (
                f"Web application firewall blocked SQL injection attempt "
                f"from {src}. Payload contained UNION SELECT, DROP TABLE "
                f"patterns. Target: login endpoint /api/auth. "
                f"400 requests in 2 minutes from same source."
            ),
            source_ip    = src,
            dest_ip      = dst,
            dest_port    = 443,
            protocol     = "HTTPS",
            mitre_id     = m["id"],
            mitre_tactic = m["tactic"],
            mitre_name   = m["name"],
            tags         = ["web-attack", "sqli", "waf", "application"],
            raw_log      = (
                f'[{self._ts(minutes_ago)}] BLOCK modsecurity: '
                f'SQL Injection detected from {src} '
                f'URI=/api/auth payload="admin\' OR 1=1--"'
            ),
        )

    def generate_batch(self, count: int = 20) -> List[Alert]:
        """Generate a realistic mix of alerts over the past 24 hours"""
        generators = [
            self.brute_force_alert,
            self.port_scan_alert,
            self.ddos_alert,
            self.lateral_movement_alert,
            self.data_exfiltration_alert,
            self.malware_beacon_alert,
            self.privilege_escalation_alert,
            self.sql_injection_alert,
        ]

        # Weighted distribution — brute force & port scans most common
        weights = [25, 20, 10, 15, 10, 10, 5, 5]
        alerts  = []

        for i in range(count):
            gen         = random.choices(generators, weights=weights, k=1)[0]
            minutes_ago = random.randint(0, 1440)   # last 24 hours
            alerts.append(gen(minutes_ago))

        # Sort by timestamp descending
        alerts.sort(key=lambda a: a.timestamp, reverse=True)
        return alerts


# ══════════════════════════════════════════════════════
#  DETECTION ENGINE
# ══════════════════════════════════════════════════════

class DetectionEngine:
    """
    Rule-based + threshold detection engine.
    Analyzes network events and generates alerts
    when thresholds or patterns are triggered.
    """

    RULES = [
        {
            "id":        "RULE-001",
            "name":      "SSH Brute Force",
            "condition": "Failed SSH logins > 10 in 60s",
            "severity":  "HIGH",
            "type":      "brute_force",
            "mitre":     "T1110",
        },
        {
            "id":        "RULE-002",
            "name":      "Port Scan Detection",
            "condition": "SYN packets to > 50 ports in 10s",
            "severity":  "MEDIUM",
            "type":      "port_scan",
            "mitre":     "T1046",
        },
        {
            "id":        "RULE-003",
            "name":      "DDoS Flood",
            "condition": "Traffic > 10Gbps sustained",
            "severity":  "CRITICAL",
            "type":      "ddos",
            "mitre":     "T1499",
        },
        {
            "id":        "RULE-004",
            "name":      "Lateral Movement SMB",
            "condition": "Internal host connects to > 5 SMB hosts in 10min",
            "severity":  "HIGH",
            "type":      "lateral_movement",
            "mitre":     "T1021",
        },
        {
            "id":        "RULE-005",
            "name":      "Data Exfiltration",
            "condition": "Outbound data > 10x baseline in 5min",
            "severity":  "CRITICAL",
            "type":      "data_exfiltration",
            "mitre":     "T1041",
        },
        {
            "id":        "RULE-006",
            "name":      "C2 Beaconing",
            "condition": "Periodic connections to known C2 IP",
            "severity":  "HIGH",
            "type":      "malware_beacon",
            "mitre":     "T1071",
        },
        {
            "id":        "RULE-007",
            "name":      "Privilege Escalation",
            "condition": "Sudo exploit pattern in auditd logs",
            "severity":  "CRITICAL",
            "type":      "privilege_escalation",
            "mitre":     "T1068",
        },
        {
            "id":        "RULE-008",
            "name":      "SQL Injection",
            "condition": "WAF: SQL keywords in request params",
            "severity":  "HIGH",
            "type":      "sql_injection",
            "mitre":     "T1190",
        },
    ]

    @classmethod
    def get_rules(cls) -> List[Dict]:
        return cls.RULES

    @classmethod
    def get_stats(cls, alerts: List[Alert]) -> Dict:
        """Compute SOC statistics from alert list"""
        total      = len(alerts)
        by_severity = defaultdict(int)
        by_type     = defaultdict(int)
        by_status   = defaultdict(int)
        by_tactic   = defaultdict(int)

        for a in alerts:
            by_severity[a.severity]     += 1
            by_type[a.alert_type]       += 1
            by_status[a.status]         += 1
            by_tactic[a.mitre_tactic]   += 1

        open_critical = sum(
            1 for a in alerts
            if a.severity == "CRITICAL" and a.status == "open"
        )

        return {
            "total_alerts":   total,
            "open_alerts":    by_status.get("open", 0),
            "closed_alerts":  by_status.get("closed", 0),
            "open_critical":  open_critical,
            "by_severity":    dict(by_severity),
            "by_type":        dict(by_type),
            "by_status":      dict(by_status),
            "by_tactic":      dict(by_tactic),
            "mean_time_open": f"{random.randint(2, 48)}h {random.randint(0,59)}m",
        }
