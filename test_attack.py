"""
Advanced Attack Simulation Script for NIDRS Testing
Simulates realistic attack patterns including full kill chains.
Run this to verify detection capabilities and test correlation.
"""

import requests
import time
import random
import argparse
from datetime import datetime, timedelta
from typing import List, Dict

BASE_URL = "http://localhost:8000"

# Color codes for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

def log_event(log: Dict, description: str = "") -> bool:
    """Send log event to the API and return success status"""
    try:
        response = requests.post(f"{BASE_URL}/api/logs/ingest", json=log, timeout=5)
        return response.status_code == 200
    except Exception as e:
        print(f"{Colors.RED}  Error: {e}{Colors.END}")
        return False

def print_phase(phase: str, description: str):
    """Print attack phase header"""
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.YELLOW}[{phase}]{Colors.END} {description}")
    print(f"{Colors.CYAN}{'='*60}{Colors.END}")

def print_action(action: str, success: bool = True):
    """Print action result"""
    status = f"{Colors.GREEN}✓{Colors.END}" if success else f"{Colors.RED}✗{Colors.END}"
    print(f"  {status} {action}")

# ============ INDIVIDUAL ATTACK SIMULATIONS ============

def test_brute_force_simulation(num_attempts: int = 15, success_at_end: bool = True):
    """Simulate realistic brute force attack with timing patterns"""
    print_phase("BRUTE FORCE", "Simulating password spray/brute force attack")
    
    attacker_ip = f"185.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    target_users = ["admin", "administrator", "root", "user", "guest"]
    
    print(f"  {Colors.MAGENTA}Attacker IP: {attacker_ip}{Colors.END}")
    print(f"  {Colors.MAGENTA}Target users: {', '.join(target_users)}{Colors.END}")
    print()
    
    # Phase 1: Password spray across users
    for user in target_users:
        for i in range(num_attempts // len(target_users)):
            log = {
                "timestamp": datetime.now().isoformat(),
                "source_type": "windows",
                "event_type": "login",
                "action": "failure",
                "src_ip": attacker_ip,
                "user": user,
                "hostname": "DC01.corp.local",
                "message": f"Failed login attempt for {user} - invalid password",
                "severity": "high",
                "metadata": {
                    "event_id": 4625,
                    "logon_type": 3,
                    "failure_reason": "Bad password",
                    "workstation": f"ATTACKER-{random.randint(100,999)}"
                }
            }
            success = log_event(log)
            print_action(f"Failed login: {user} (attempt {i+1})", success)
            time.sleep(random.uniform(0.05, 0.2))  # Variable timing to seem more realistic
    
    # Phase 2: Successful login (if enabled)
    if success_at_end:
        time.sleep(0.5)
        log = {
            "timestamp": datetime.now().isoformat(),
            "source_type": "windows",
            "event_type": "login",
            "action": "success",
            "src_ip": attacker_ip,
            "user": "admin",
            "hostname": "DC01.corp.local",
            "message": "Successful login after multiple failures - POTENTIAL BREACH",
            "severity": "critical",
            "metadata": {
                "event_id": 4624,
                "logon_type": 3,
                "elevated": True
            }
        }
        success = log_event(log)
        print()
        print(f"  {Colors.RED}{Colors.BOLD}⚠ BREACH: Successful login achieved!{Colors.END}")
    
    return attacker_ip


def test_port_scan_simulation(scan_type: str = "stealth"):
    """Simulate various port scan types"""
    print_phase("RECONNAISSANCE", f"Simulating {scan_type} port scan")
    
    attacker_ip = f"10.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    target_ip = "192.168.1.10"
    
    print(f"  {Colors.MAGENTA}Scanner IP: {attacker_ip}{Colors.END}")
    print(f"  {Colors.MAGENTA}Target IP: {target_ip}{Colors.END}")
    print()
    
    # Define scan patterns
    if scan_type == "stealth":
        ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 8080, 8443]
        flags = "SYN"
        delay = 0.3
    elif scan_type == "aggressive":
        ports = list(range(1, 100)) + list(range(3300, 3400)) + list(range(8000, 8100))
        flags = "SYN,ACK"
        delay = 0.01
    else:  # comprehensive
        ports = list(range(1, 1025))
        flags = "SYN"
        delay = 0.05
    
    open_ports = [22, 80, 443, 3306, 3389]  # Simulate some open ports
    
    for port in ports[:50]:  # Limit for demo
        action = "allow" if port in open_ports else "deny"
        log = {
            "timestamp": datetime.now().isoformat(),
            "source_type": "firewall",
            "event_type": "connection",
            "action": action,
            "src_ip": attacker_ip,
            "dst_ip": target_ip,
            "src_port": random.randint(40000, 65000),
            "dst_port": port,
            "protocol": "tcp",
            "message": f"Port scan detected: {flags} to port {port}",
            "severity": "medium",
            "metadata": {
                "tcp_flags": flags,
                "bytes": 60,
                "interface": "eth0"
            }
        }
        success = log_event(log)
        status = f"{Colors.GREEN}OPEN{Colors.END}" if port in open_ports else f"{Colors.WHITE}closed{Colors.END}"
        print_action(f"Port {port:5d} [{status}]", success)
        time.sleep(delay)
    
    return attacker_ip


def test_ddos_simulation(attack_type: str = "syn_flood", duration: int = 5):
    """Simulate various DDoS attack patterns"""
    print_phase("DDoS ATTACK", f"Simulating {attack_type.replace('_', ' ').upper()}")
    
    target_ip = "192.168.1.1"
    botnet_size = random.randint(50, 200)
    
    print(f"  {Colors.MAGENTA}Target: {target_ip}{Colors.END}")
    print(f"  {Colors.MAGENTA}Botnet size: ~{botnet_size} hosts{Colors.END}")
    print(f"  {Colors.MAGENTA}Duration: {duration}s{Colors.END}")
    print()
    
    attack_configs = {
        "syn_flood": {"protocol": "TCP", "flags": "SYN", "port": 80, "size": 60},
        "udp_flood": {"protocol": "UDP", "flags": None, "port": 53, "size": 512},
        "http_flood": {"protocol": "TCP", "flags": "PSH,ACK", "port": 80, "size": 1500},
        "slowloris": {"protocol": "TCP", "flags": "PSH", "port": 80, "size": 100},
        "amplification": {"protocol": "UDP", "flags": None, "port": 123, "size": 4096}
    }
    
    config = attack_configs.get(attack_type, attack_configs["syn_flood"])
    packets_sent = 0
    bytes_sent = 0
    sources_used = set()
    
    start_time = time.time()
    while time.time() - start_time < duration:
        # Generate random botnet source
        src_ip = f"{random.choice(['203.0.113', '198.51.100', '185.220.101'])}.{random.randint(1, 254)}"
        sources_used.add(src_ip)
        
        log = {
            "timestamp": datetime.now().isoformat(),
            "source_type": "network",
            "event_type": "packet",
            "src_ip": src_ip,
            "dst_ip": target_ip,
            "src_port": random.randint(1024, 65535),
            "dst_port": config["port"],
            "protocol": config["protocol"],
            "message": f"{attack_type} attack packet",
            "severity": "high",
            "metadata": {
                "length": config["size"],
                "flags": config["flags"],
                "ttl": random.randint(40, 64)
            }
        }
        log_event(log)
        packets_sent += 1
        bytes_sent += config["size"]
        
        if packets_sent % 50 == 0:
            rate = packets_sent / (time.time() - start_time)
            print(f"  {Colors.YELLOW}⚡ {packets_sent} packets | {rate:.0f} pps | {len(sources_used)} sources{Colors.END}")
        
        time.sleep(0.005)  # High rate
    
    print()
    print(f"  {Colors.RED}{Colors.BOLD}Attack Summary:{Colors.END}")
    print(f"    Packets: {packets_sent}")
    print(f"    Data: {bytes_sent / 1024:.1f} KB")
    print(f"    Sources: {len(sources_used)}")
    print(f"    Rate: {packets_sent / duration:.0f} pps")


def test_lateral_movement_simulation(compromised_ip: str = None):
    """Simulate lateral movement through internal network"""
    print_phase("LATERAL MOVEMENT", "Simulating internal network propagation")
    
    if not compromised_ip:
        compromised_ip = "192.168.1.50"
    
    internal_targets = [
        ("192.168.1.10", "FILE-SERVER", "SMB file access"),
        ("192.168.1.20", "DB-SERVER", "Database connection"),
        ("192.168.1.30", "WEB-SERVER", "Web admin panel"),
        ("192.168.1.40", "BACKUP-SERVER", "Backup system access"),
        ("192.168.1.100", "DC01", "Domain controller")
    ]
    
    print(f"  {Colors.MAGENTA}Compromised host: {compromised_ip}{Colors.END}")
    print(f"  {Colors.MAGENTA}Targets: {len(internal_targets)} internal systems{Colors.END}")
    print()
    
    for target_ip, hostname, description in internal_targets:
        # First: SMB/RDP connection attempt
        log = {
            "timestamp": datetime.now().isoformat(),
            "source_type": "network",
            "event_type": "connection",
            "action": "allow",
            "src_ip": compromised_ip,
            "dst_ip": target_ip,
            "dst_port": random.choice([445, 3389, 5985]),
            "protocol": "TCP",
            "message": f"Internal connection to {hostname}",
            "severity": "low",
            "metadata": {"hostname": hostname}
        }
        log_event(log)
        
        time.sleep(0.1)
        
        # Then: Successful authentication
        log = {
            "timestamp": datetime.now().isoformat(),
            "source_type": "windows",
            "event_type": "login",
            "action": "success",
            "src_ip": compromised_ip,
            "dst_ip": target_ip,
            "hostname": hostname,
            "user": "svc_backup",  # Service account
            "message": f"Remote login to {hostname} - {description}",
            "severity": "medium",
            "metadata": {
                "event_id": 4624,
                "logon_type": 3,
                "auth_package": "NTLM"
            }
        }
        success = log_event(log)
        print_action(f"Moved to {hostname} ({target_ip}) - {description}", success)
        time.sleep(0.3)
    
    return internal_targets


def test_privilege_escalation_simulation():
    """Simulate privilege escalation attempts"""
    print_phase("PRIVILEGE ESCALATION", "Simulating privilege elevation")
    
    src_ip = "192.168.1.50"
    
    print(f"  {Colors.MAGENTA}Source: {src_ip}{Colors.END}")
    print()
    
    # Windows privilege escalation events
    priv_events = [
        (4672, "Special privileges assigned to new logon", "admin"),
        (4673, "A privileged service was called", "SYSTEM"),
        (4674, "Operation attempted on privileged object", "admin"),
        (4688, "New process created with elevated privileges", "admin"),
        (4697, "Service installed in the system", "SYSTEM"),
    ]
    
    for event_id, message, user in priv_events:
        log = {
            "timestamp": datetime.now().isoformat(),
            "source_type": "windows",
            "event_type": "privilege",
            "action": "success",
            "src_ip": src_ip,
            "user": user,
            "hostname": "WORKSTATION-01",
            "message": message,
            "severity": "high",
            "metadata": {
                "event_id": event_id,
                "privilege": "SeDebugPrivilege",
                "process": "mimikatz.exe" if event_id == 4688 else None
            }
        }
        success = log_event(log)
        print_action(f"Event {event_id}: {message}", success)
        time.sleep(0.2)
    
    # Linux sudo events
    sudo_commands = [
        "sudo su -",
        "sudo cat /etc/shadow",
        "sudo chmod 777 /root",
        "sudo useradd backdoor -G wheel"
    ]
    
    print()
    for cmd in sudo_commands:
        log = {
            "timestamp": datetime.now().isoformat(),
            "source_type": "syslog",
            "event_type": "privilege",
            "action": "success",
            "src_ip": src_ip,
            "user": "compromised_user",
            "hostname": "linux-server",
            "message": f"sudo: {cmd}",
            "severity": "high",
            "metadata": {
                "facility": "auth",
                "program": "sudo"
            }
        }
        success = log_event(log)
        print_action(f"sudo: {cmd}", success)
        time.sleep(0.15)


def test_data_exfiltration_simulation():
    """Simulate data exfiltration"""
    print_phase("DATA EXFILTRATION", "Simulating data theft")
    
    src_ip = "192.168.1.50"
    external_c2 = f"185.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    
    print(f"  {Colors.MAGENTA}Source (internal): {src_ip}{Colors.END}")
    print(f"  {Colors.MAGENTA}C2 Server: {external_c2}{Colors.END}")
    print()
    
    total_bytes = 0
    chunk_sizes = [1024*1024, 2*1024*1024, 5*1024*1024, 10*1024*1024, 500*1024]  # Various sizes
    
    for i in range(50):
        chunk = random.choice(chunk_sizes)
        total_bytes += chunk
        
        log = {
            "timestamp": datetime.now().isoformat(),
            "source_type": "network",
            "event_type": "connection",
            "action": "allow",
            "src_ip": src_ip,
            "dst_ip": external_c2,
            "src_port": random.randint(40000, 65000),
            "dst_port": random.choice([443, 8443, 53, 123]),  # Common exfil ports
            "protocol": random.choice(["TCP", "UDP"]),
            "message": "Outbound data transfer",
            "severity": "medium",
            "metadata": {
                "length": chunk,
                "bytes_out": chunk,
                "application": "encrypted"
            }
        }
        log_event(log)
        
        if (i + 1) % 10 == 0:
            print(f"  {Colors.YELLOW}📤 Exfiltrated: {total_bytes / (1024*1024):.1f} MB{Colors.END}")
        
        time.sleep(0.05)
    
    print()
    print(f"  {Colors.RED}{Colors.BOLD}Total exfiltrated: {total_bytes / (1024*1024):.1f} MB{Colors.END}")


def test_ransomware_simulation():
    """Simulate ransomware behavior patterns"""
    print_phase("RANSOMWARE", "Simulating ransomware indicators")
    
    src_ip = "192.168.1.50"
    
    print(f"  {Colors.MAGENTA}Infected host: {src_ip}{Colors.END}")
    print()
    
    # File encryption events
    file_extensions = [".docx", ".xlsx", ".pdf", ".jpg", ".sql", ".bak"]
    directories = ["C:\\Users\\admin\\Documents", "C:\\Shares\\Finance", "D:\\Backups"]
    
    print(f"  {Colors.YELLOW}Phase 1: Mass file access/modification{Colors.END}")
    for _ in range(20):
        ext = random.choice(file_extensions)
        dir_path = random.choice(directories)
        log = {
            "timestamp": datetime.now().isoformat(),
            "source_type": "windows",
            "event_type": "file_access",
            "action": "modify",
            "src_ip": src_ip,
            "user": "SYSTEM",
            "hostname": "WORKSTATION-01",
            "message": f"File modified: {dir_path}\\file_{random.randint(1,999)}{ext}.encrypted",
            "severity": "high",
            "metadata": {
                "event_id": 4663,
                "access_mask": "WriteData",
                "process": "unknown.exe"
            }
        }
        log_event(log)
        time.sleep(0.02)
    
    print_action("Mass file encryption detected", True)
    
    # Shadow copy deletion
    print(f"\n  {Colors.YELLOW}Phase 2: Shadow copy deletion{Colors.END}")
    log = {
        "timestamp": datetime.now().isoformat(),
        "source_type": "windows",
        "event_type": "process",
        "action": "create",
        "src_ip": src_ip,
        "user": "SYSTEM",
        "message": "vssadmin.exe delete shadows /all /quiet",
        "severity": "critical",
        "metadata": {
            "event_id": 4688,
            "process": "vssadmin.exe",
            "commandline": "delete shadows /all /quiet"
        }
    }
    log_event(log)
    print_action("Shadow copy deletion command executed", True)
    
    # Ransom note creation
    print(f"\n  {Colors.YELLOW}Phase 3: Ransom note deployment{Colors.END}")
    log = {
        "timestamp": datetime.now().isoformat(),
        "source_type": "windows",
        "event_type": "file_access",
        "action": "create",
        "src_ip": src_ip,
        "user": "SYSTEM",
        "message": "File created: README_RESTORE_FILES.txt",
        "severity": "critical",
        "metadata": {
            "event_id": 4663,
            "filename": "README_RESTORE_FILES.txt"
        }
    }
    log_event(log)
    print_action("Ransom note created", True)


# ============ FULL ATTACK CHAIN SIMULATIONS ============

def simulate_apt_kill_chain():
    """Simulate complete APT attack kill chain"""
    print(f"\n{Colors.BOLD}{Colors.RED}{'#'*60}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.RED}   FULL APT KILL CHAIN SIMULATION{Colors.END}")
    print(f"{Colors.BOLD}{Colors.RED}{'#'*60}{Colors.END}")
    
    print(f"\n{Colors.CYAN}This simulation follows the Cyber Kill Chain:{Colors.END}")
    print("  1. Reconnaissance → 2. Initial Access → 3. Execution")
    print("  4. Privilege Escalation → 5. Lateral Movement")
    print("  6. Collection → 7. Exfiltration")
    print()
    input(f"{Colors.YELLOW}Press Enter to begin simulation...{Colors.END}")
    
    # Stage 1: Reconnaissance
    attacker_ip = test_port_scan_simulation("stealth")
    time.sleep(2)
    
    # Stage 2: Initial Access (Brute Force)
    attacker_ip = test_brute_force_simulation(num_attempts=20, success_at_end=True)
    time.sleep(2)
    
    # Stage 3 & 4: Privilege Escalation
    test_privilege_escalation_simulation()
    time.sleep(2)
    
    # Stage 5: Lateral Movement
    test_lateral_movement_simulation("192.168.1.50")
    time.sleep(2)
    
    # Stage 6 & 7: Collection and Exfiltration
    test_data_exfiltration_simulation()
    
    print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.GREEN}   KILL CHAIN SIMULATION COMPLETE{Colors.END}")
    print(f"{Colors.BOLD}{Colors.GREEN}{'='*60}{Colors.END}")


def simulate_ransomware_attack():
    """Simulate complete ransomware attack"""
    print(f"\n{Colors.BOLD}{Colors.RED}{'#'*60}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.RED}   RANSOMWARE ATTACK SIMULATION{Colors.END}")
    print(f"{Colors.BOLD}{Colors.RED}{'#'*60}{Colors.END}")
    print()
    input(f"{Colors.YELLOW}Press Enter to begin simulation...{Colors.END}")
    
    # Initial compromise
    test_brute_force_simulation(num_attempts=10, success_at_end=True)
    time.sleep(1)
    
    # Privilege escalation
    test_privilege_escalation_simulation()
    time.sleep(1)
    
    # Lateral movement to spread
    test_lateral_movement_simulation()
    time.sleep(1)
    
    # Ransomware execution
    test_ransomware_simulation()
    
    print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.GREEN}   RANSOMWARE SIMULATION COMPLETE{Colors.END}")
    print(f"{Colors.BOLD}{Colors.GREEN}{'='*60}{Colors.END}")


# ============ RESULTS AND ANALYSIS ============

def run_correlation():
    """Trigger correlation engine"""
    print(f"\n{Colors.CYAN}[ENGINE] Running Correlation Analysis...{Colors.END}")
    try:
        response = requests.post(f"{BASE_URL}/api/correlation/run", timeout=10)
        result = response.json()
        print(f"  Correlation completed: {result}")
        return result
    except Exception as e:
        print(f"  {Colors.RED}Error running correlation: {e}{Colors.END}")
        return None


def check_results():
    """Comprehensive results check"""
    print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.GREEN}          DETECTION RESULTS{Colors.END}")
    print(f"{Colors.BOLD}{Colors.GREEN}{'='*60}{Colors.END}")
    
    try:
        # Correlated Threats
        print(f"\n{Colors.BOLD}[CORRELATED THREATS]{Colors.END}")
        response = requests.get(f"{BASE_URL}/api/correlation/threats", timeout=5)
        threats = response.json()
        if threats:
            for t in threats:
                severity_color = {
                    "critical": Colors.RED,
                    "high": Colors.YELLOW,
                    "medium": Colors.CYAN,
                    "low": Colors.WHITE
                }.get(t['severity'], Colors.WHITE)
                
                print(f"  {severity_color}● {t['attack_type'].upper()}{Colors.END}")
                print(f"    Confidence: {t['confidence']*100:.0f}% | Severity: {t['severity']}")
                print(f"    Sources: {', '.join(t['source_ips'][:3])}")
                print(f"    Stage: {t.get('stage', 'unknown')}")
                if t.get('narrative'):
                    print(f"    {Colors.WHITE}{t['narrative'][:100]}...{Colors.END}")
                print()
        else:
            print(f"  {Colors.YELLOW}No correlated threats detected yet{Colors.END}")
        
        # Attack Chains
        print(f"\n{Colors.BOLD}[ATTACK CHAINS]{Colors.END}")
        response = requests.get(f"{BASE_URL}/api/chains/active", timeout=5)
        chains = response.json()
        if chains:
            for c in chains:
                print(f"  {Colors.RED}⚠ {c['name']}{Colors.END}")
                print(f"    Severity: {c['severity']} | Stages: {len(c.get('stages', []))}")
                if c.get('stages'):
                    print(f"    Progression: {' → '.join(c['stages'][:5])}")
                print()
        else:
            print(f"  {Colors.YELLOW}No attack chains detected yet{Colors.END}")
        
        # Prioritized Alerts
        print(f"\n{Colors.BOLD}[TOP PRIORITIZED ALERTS]{Colors.END}")
        response = requests.get(f"{BASE_URL}/api/alerts/prioritized?limit=10", timeout=5)
        alerts = response.json()
        if alerts:
            print(f"  {'Score':>6} | {'Type':<20} | {'Source IP':<15} | Severity")
            print(f"  {'-'*6}-+-{'-'*20}-+-{'-'*15}-+-{'-'*10}")
            for a in alerts[:10]:
                score = a.get('priority_score', 0)
                alert_type = a.get('attack_type', a.get('type', 'unknown'))[:20]
                src_ip = a.get('src_ip', 'N/A')[:15]
                severity = a.get('severity', 'N/A')
                print(f"  {score:>6.1f} | {alert_type:<20} | {src_ip:<15} | {severity}")
        else:
            print(f"  {Colors.YELLOW}No prioritized alerts yet{Colors.END}")
        
        # Alert Statistics
        print(f"\n{Colors.BOLD}[ALERT STATISTICS]{Colors.END}")
        response = requests.get(f"{BASE_URL}/api/alerts/statistics", timeout=5)
        stats = response.json()
        print(f"  Total processed: {stats.get('total_processed', 0)}")
        print(f"  Active alerts:   {stats.get('active_alerts', 0)}")
        print(f"  Suppressed:      {stats.get('suppressed', 0)}")
        print(f"  Reduction rate:  {stats.get('reduction_rate', 0):.1f}%")
        
        # Threat Summary
        print(f"\n{Colors.BOLD}[THREAT SUMMARY]{Colors.END}")
        response = requests.get(f"{BASE_URL}/api/correlation/summary", timeout=5)
        summary = response.json()
        if summary.get('by_type'):
            print(f"  By Type: {summary.get('by_type', {})}")
        if summary.get('by_severity'):
            print(f"  By Severity: {summary.get('by_severity', {})}")
        if summary.get('by_stage'):
            print(f"  By Stage: {summary.get('by_stage', {})}")
        
    except requests.exceptions.ConnectionError:
        print(f"\n{Colors.RED}ERROR: Cannot connect to server{Colors.END}")
    except Exception as e:
        print(f"\n{Colors.RED}ERROR: {e}{Colors.END}")


def interactive_menu():
    """Interactive menu for selecting attack simulations"""
    while True:
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}        NIDRS ATTACK SIMULATION MENU{Colors.END}")
        print(f"{Colors.CYAN}{'='*60}{Colors.END}")
        print(f"""
  {Colors.BOLD}Individual Attacks:{Colors.END}
    1. Brute Force Attack
    2. Port Scan (Stealth)
    3. Port Scan (Aggressive)
    4. DDoS - SYN Flood
    5. DDoS - UDP Flood
    6. DDoS - HTTP Flood
    7. Lateral Movement
    8. Privilege Escalation
    9. Data Exfiltration
   10. Ransomware
   
  {Colors.BOLD}Full Attack Chains:{Colors.END}
   11. APT Kill Chain (Full)
   12. Ransomware Attack (Full)
   
  {Colors.BOLD}Analysis:{Colors.END}
   13. Run Correlation Engine
   14. Check Detection Results
   
  {Colors.BOLD}Other:{Colors.END}
   15. Run All Individual Tests
    0. Exit
        """)
        
        try:
            choice = input(f"{Colors.YELLOW}Select option: {Colors.END}").strip()
            
            if choice == "0":
                print(f"\n{Colors.GREEN}Exiting...{Colors.END}")
                break
            elif choice == "1":
                test_brute_force_simulation()
            elif choice == "2":
                test_port_scan_simulation("stealth")
            elif choice == "3":
                test_port_scan_simulation("aggressive")
            elif choice == "4":
                test_ddos_simulation("syn_flood", 3)
            elif choice == "5":
                test_ddos_simulation("udp_flood", 3)
            elif choice == "6":
                test_ddos_simulation("http_flood", 3)
            elif choice == "7":
                test_lateral_movement_simulation()
            elif choice == "8":
                test_privilege_escalation_simulation()
            elif choice == "9":
                test_data_exfiltration_simulation()
            elif choice == "10":
                test_ransomware_simulation()
            elif choice == "11":
                simulate_apt_kill_chain()
            elif choice == "12":
                simulate_ransomware_attack()
            elif choice == "13":
                run_correlation()
            elif choice == "14":
                check_results()
            elif choice == "15":
                run_all_tests()
            else:
                print(f"{Colors.RED}Invalid option{Colors.END}")
                
        except KeyboardInterrupt:
            print(f"\n{Colors.GREEN}Interrupted. Exiting...{Colors.END}")
            break


def run_all_tests():
    """Run all individual attack simulations"""
    print(f"\n{Colors.BOLD}Running all attack simulations...{Colors.END}")
    
    tests = [
        ("Brute Force", lambda: test_brute_force_simulation()),
        ("Port Scan", lambda: test_port_scan_simulation("stealth")),
        ("DDoS", lambda: test_ddos_simulation("syn_flood", 2)),
        ("Lateral Movement", lambda: test_lateral_movement_simulation()),
        ("Privilege Escalation", lambda: test_privilege_escalation_simulation()),
        ("Data Exfiltration", lambda: test_data_exfiltration_simulation()),
    ]
    
    for name, test_func in tests:
        try:
            test_func()
            time.sleep(1)
        except Exception as e:
            print(f"{Colors.RED}Error in {name}: {e}{Colors.END}")
    
    print(f"\n{Colors.GREEN}All tests completed. Running correlation...{Colors.END}")
    time.sleep(2)
    run_correlation()
    time.sleep(2)
    check_results()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NIDRS Attack Simulation Tool")
    parser.add_argument("--auto", action="store_true", help="Run all tests automatically")
    parser.add_argument("--apt", action="store_true", help="Run APT kill chain simulation")
    parser.add_argument("--ransomware", action="store_true", help="Run ransomware simulation")
    parser.add_argument("--url", default="http://localhost:8000", help="API base URL")
    args = parser.parse_args()
    
    BASE_URL = args.url
    
    print(f"{Colors.BOLD}{Colors.CYAN}")
    print("="*60)
    print("     NIDRS - ATTACK SIMULATION TOOL")
    print("     Network Intrusion Detection & Response System")
    print("="*60)
    print(f"{Colors.END}")
    print(f"  Target: {BASE_URL}")
    print(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Check server connectivity
    try:
        response = requests.get(f"{BASE_URL}/api/status", timeout=5)
        print(f"  Status: {Colors.GREEN}Server Online ✓{Colors.END}")
    except:
        print(f"  Status: {Colors.RED}Server Offline ✗{Colors.END}")
        print(f"\n{Colors.RED}ERROR: Cannot connect to {BASE_URL}{Colors.END}")
        print("Make sure the server is running: uvicorn backend.main:app --reload")
        exit(1)
    
    try:
        if args.auto:
            run_all_tests()
        elif args.apt:
            simulate_apt_kill_chain()
            run_correlation()
            check_results()
        elif args.ransomware:
            simulate_ransomware_attack()
            run_correlation()
            check_results()
        else:
            interactive_menu()
    except KeyboardInterrupt:
        print(f"\n{Colors.GREEN}Simulation interrupted.{Colors.END}")
    except Exception as e:
        print(f"\n{Colors.RED}Error: {e}{Colors.END}")
