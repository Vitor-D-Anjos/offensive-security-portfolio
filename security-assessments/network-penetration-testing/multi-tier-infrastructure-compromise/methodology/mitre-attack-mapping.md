# MITRE ATT&CK Framework Mapping
## Multi-Tier Infrastructure Compromise Assessment

**Assessment Date:** October 2025  
**Framework Version:** ATT&CK v14  
**Classification:** CONFIDENTIAL

---

## Executive Overview

This document maps observed techniques, tactics, and procedures (TTPs) from the penetration test to the MITRE ATT&CK framework. The assessment demonstrated 23 distinct techniques across 10 tactical categories, providing a comprehensive view of adversary behavior patterns that could be employed against the target infrastructure.

---

## Attack Chain Visualization

```
[Reconnaissance] → [Initial Access] → [Execution] → [Persistence]
                                          ↓
[Discovery] ← [Credential Access] ← [Lateral Movement]
     ↓
[Privilege Escalation] → [Defense Evasion] → [Impact]
```

---

## Detailed Technique Mapping

### Reconnaissance (TA0043)

**Objective:** Gather information to plan future operations

#### T1046: Network Service Discovery
**Description:** Performed network scanning to identify live hosts and available services.

**Tools Used:**
- Nmap 7.94SVN

**Commands Executed:**
```bash
nmap -sV -A -p- 10.50.100.10
nmap -sV -A -p- 10.50.100.20
```

**Systems Targeted:**
- gateway.corp.local (10.50.100.10)
- webapps.corp.local (10.50.100.20)

**Results:**
- Identified SMB service (port 445)
- Identified HTTP service (port 80)
- Identified MySQL service (port 3306)
- Identified SSH service (port 22)

**Detection Opportunities:**
- Cannot detect offline cracking
- Focus on preventing hash extraction
- Strong password policies

---

### Discovery (TA0007)

**Objective:** Understand the environment and internal network

#### T1082: System Information Discovery
**Description:** Gathered detailed system information from compromised hosts.

**Information Collected:**
- Operating system and version
- Kernel version
- Installed software versions
- System architecture

**Commands:**
```bash
uname -a
cat /etc/os-release
hostnamectl
```

**Detection Opportunities:**
- Command execution monitoring
- EDR behavioral analysis

---

#### T1083: File and Directory Discovery
**Description:** Enumerated file systems to locate sensitive data and configuration files.

**Commands:**
```bash
ls -la /home/
ls -la /var/www/
ls -la /etc/
find / -name "*.conf"
find / -perm -4000
```

**Discovery Results:**
- Application directories
- Configuration files
- SUID binaries
- User home directories

**Detection Opportunities:**
- File access pattern analysis
- Unusual directory traversal
- Rapid file enumeration detection

---

#### T1087.001: Account Discovery: Local Account
**Description:** Enumerated local user accounts on compromised systems.

**Methods:**
```bash
cat /etc/passwd
cat /etc/group
w
who
```

**Accounts Discovered:**
- System accounts
- Administrative accounts
- Service accounts

**Detection Opportunities:**
- File access auditing
- Account enumeration detection

---

#### T1018: Remote System Discovery
**Description:** Discovered additional hosts on internal network through network scanning.

**Scanning Tools:**
- Metasploit auxiliary/scanner/portscan/tcp
- Nmap (through proxy)

**Networks Discovered:**
- 10.50.100.0/24 (external network)
- 172.16.50.0/24 (internal network)

**Hosts Identified:**
- 172.16.50.5 (gateway)
- 172.16.50.10 (application server)
- 172.16.50.15 (vault system)

**Detection Opportunities:**
- Network IDS/IPS
- Internal port scan detection
- Unusual traffic patterns

---

#### T1046: Network Service Discovery
**Description:** Identified services running on discovered hosts.

**Ports Scanned:**
- 22 (SSH)
- 80 (HTTP)
- 111 (RPC)
- 443 (HTTPS)
- 3306 (MySQL)

**Services Identified:**
- OpenSSH servers
- Apache web servers
- MySQL databases

**Detection Opportunities:**
- Network monitoring
- Service connection logging

---

#### T1049: System Network Connections Discovery
**Description:** Examined active network connections and listening services.

**Commands:**
```bash
netstat -tulpn
ss -tulpn
ip addr show
ip route show
```

**Information Gathered:**
- Active connections
- Listening services
- Network interfaces
- Routing configuration

**Detection Opportunities:**
- Command execution logging
- Process monitoring

---

#### T1057: Process Discovery
**Description:** Enumerated running processes to identify security tools and opportunities.

**Commands:**
```bash
ps aux
ps -ef
top
```

**Targets Identified:**
- Running services
- Security tools (none found)
- User processes

**Detection Opportunities:**
- Process execution monitoring
- Command-line logging

---

### Lateral Movement (TA0008)

**Objective:** Move through the environment to reach target systems

#### T1021.004: Remote Services: SSH
**Description:** Used SSH to access internal systems after compromising credentials.

**SSH Connections:**
- admin_vault@vault.corp.internal (172.16.50.15)

**Authentication:**
- Password-based (brute forced)

**Detection Opportunities:**
- SSH authentication logging
- Unusual SSH source detection
- Behavioral analytics

---

#### T1090: Proxy
**Description:** Used compromised host (webapps.corp.local) as pivot point to access internal network.

**Sub-technique:** T1090.001 (Internal Proxy)

**Pivot Configuration:**
- Meterpreter autoroute
- Port forwarding through Meterpreter

**Commands:**
```bash
run autoroute -s 172.16.50.0/24
portfwd add -L 127.0.0.1 -l 2222 -r 172.16.50.15 -p 22
```

**Networks Accessed:**
- 10.50.100.0/24 → 172.16.50.0/24

**Detection Opportunities:**
- Network flow analysis
- Unusual traffic patterns
- Proxy detection rules

---

#### T1563: Remote Service Session Hijacking
**Description:** Established multiple sessions through compromised systems.

**Session Types:**
- Reverse shell sessions
- Meterpreter sessions
- SSH sessions

**Detection Opportunities:**
- Session monitoring
- Multiple concurrent session detection
- Unusual session characteristics

---

### Collection (TA0009)

**Objective:** Gather information of interest

#### T1005: Data from Local System
**Description:** Collected sensitive files and data from compromised systems.

**Data Collected:**
- Configuration files
- Credential files
- Database dumps
- User files

**Locations:**
```
/var/www/config.php
/home/admin_vault/
/root/.ssh/
```

**Detection Opportunities:**
- File access monitoring
- Data exfiltration detection
- DLP solutions

---

#### T1039: Data from Network Shared Drive
**Description:** Retrieved files from SMB network share.

**Shares Accessed:**
- //10.50.100.10/public

**Files Retrieved:**
- credentials.txt
- endpoint.txt
- readme.txt

**Detection Opportunities:**
- SMB access logging
- File download monitoring
- Network share auditing

---

### Command and Control (TA0011)

**Objective:** Communicate with compromised systems

#### T1071.001: Application Layer Protocol: Web Protocols
**Description:** Used HTTP/HTTPS for command and control through Meterpreter.

**Protocols:**
- HTTP for web shell communication
- Reverse TCP for Meterpreter

**Ports Used:**
- 4444 (reverse shell)
- 4445 (Meterpreter)

**Detection Opportunities:**
- Network traffic analysis
- Protocol anomaly detection
- Known C2 signatures

---

#### T1573.001: Encrypted Channel: Symmetric Cryptography
**Description:** Meterpreter sessions utilized encrypted communications.

**Encryption:**
- TLS for Meterpreter traffic

**Detection Opportunities:**
- Traffic pattern analysis
- Certificate inspection
- Behavioral analytics

---

#### T1095: Non-Application Layer Protocol
**Description:** Used raw TCP connections for reverse shells.

**Connections:**
- Direct TCP reverse shells
- Netcat listeners

**Detection Opportunities:**
- Unusual port usage
- Non-standard protocol detection
- Network baseline deviation

---

### Impact (TA0040)

**Objective:** Manipulate, interrupt, or destroy systems and data

#### T1485: Data Destruction (Capability)
**Description:** Root access provided capability to destroy data (not executed).

**Potential Actions:**
- Delete databases
- Remove system files
- Destroy backups

**Detection Opportunities:**
- File deletion monitoring
- Backup integrity checks
- Critical file protection

---

#### T1486: Data Encrypted for Impact (Capability)
**Description:** Administrative access enabled ransomware deployment capability (not executed).

**Potential Actions:**
- Encrypt user files
- Encrypt databases
- Demand ransom

**Detection Opportunities:**
- Unusual file encryption patterns
- Ransomware behavior detection
- File change monitoring

---

#### T1529: System Shutdown/Reboot (Capability)
**Description:** Root privileges allowed system shutdown capability (not executed).

**Potential Commands:**
```bash
shutdown -h now
reboot
systemctl poweroff
```

**Detection Opportunities:**
- System event logging
- Unauthorized shutdown detection
- Administrative action auditing

---

## Summary Statistics

### Tactics Coverage

| Tactic | Techniques Used | Detection Opportunities |
|--------|-----------------|------------------------|
| Reconnaissance (TA0043) | 3 | 9 |
| Initial Access (TA0001) | 3 | 8 |
| Execution (TA0002) | 3 | 9 |
| Persistence (TA0003) | 2 | 6 |
| Privilege Escalation (TA0004) | 2 | 8 |
| Defense Evasion (TA0005) | 2 | 6 |
| Credential Access (TA0006) | 7 | 18 |
| Discovery (TA0007) | 7 | 21 |
| Lateral Movement (TA0008) | 3 | 9 |
| Collection (TA0009) | 2 | 6 |
| Command and Control (TA0011) | 3 | 9 |
| Impact (TA0040) | 3 | 9 |

**Total Techniques Demonstrated:** 40  
**Total Detection Opportunities:** 118

---

## Detection and Mitigation Priorities

### High-Priority Detection Gaps

1. **Network Segmentation Monitoring**
   - No detection for lateral movement between networks
   - Recommendation: Deploy network IDS/IPS between segments

2. **Privileged Access Monitoring**
   - Limited detection for privilege escalation attempts
   - Recommendation: Implement EDR with behavioral analytics

3. **Credential Access Detection**
   - No monitoring for credential file access
   - Recommendation: Deploy file integrity monitoring and DLP

4. **Brute Force Detection**
   - No rate limiting or lockout mechanisms
   - Recommendation: Implement fail2ban and account lockout policies

### Recommended Detection Controls

#### Network-Based Detection
```
- Network IDS/IPS (Suricata, Snort)
- Network traffic analysis (Zeek, Moloch)
- Network behavior analytics
- DNS monitoring
```

#### Host-Based Detection
```
- EDR solution (CrowdStrike, SentinelOne, Carbon Black)
- Auditd configuration for command logging
- File integrity monitoring (AIDE, Tripwire)
- Process monitoring and analysis
```

#### Application-Based Detection
```
- Web application firewall (ModSecurity)
- Database activity monitoring
- Application-level logging
- API security monitoring
```

#### Identity-Based Detection
```
- Multi-factor authentication
- Privileged access management (PAM)
- Authentication monitoring and analytics
- Session anomaly detection
```

---

## MITRE ATT&CK Navigator Layer

To visualize this assessment in [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/), import the following techniques:

```json
{
  "name": "Multi-Tier Infrastructure Compromise",
  "versions": {
    "attack": "14",
    "navigator": "4.9.0",
    "layer": "4.5"
  },
  "domain": "enterprise-attack",
  "techniques": [
    {"techniqueID": "T1046", "tactic": "discovery", "score": 100},
    {"techniqueID": "T1087.002", "tactic": "discovery", "score": 100},
    {"techniqueID": "T1592.002", "tactic": "reconnaissance", "score": 100},
    {"techniqueID": "T1133", "tactic": "initial-access", "score": 100},
    {"techniqueID": "T1078.003", "tactic": "initial-access", "score": 100},
    {"techniqueID": "T1190", "tactic": "initial-access", "score": 100},
    {"techniqueID": "T1059.004", "tactic": "execution", "score": 100},
    {"techniqueID": "T1059.006", "tactic": "execution", "score": 100},
    {"techniqueID": "T1203", "tactic": "execution", "score": 100},
    {"techniqueID": "T1505.003", "tactic": "persistence", "score": 100},
    {"techniqueID": "T1098", "tactic": "persistence", "score": 75},
    {"techniqueID": "T1068", "tactic": "privilege-escalation", "score": 100},
    {"techniqueID": "T1548.003", "tactic": "privilege-escalation", "score": 100},
    {"techniqueID": "T1070.006", "tactic": "defense-evasion", "score": 50},
    {"techniqueID": "T1027", "tactic": "defense-evasion", "score": 100},
    {"techniqueID": "T1110.001", "tactic": "credential-access", "score": 100},
    {"techniqueID": "T1110.002", "tactic": "credential-access", "score": 100},
    {"techniqueID": "T1555", "tactic": "credential-access", "score": 100},
    {"techniqueID": "T1552.001", "tactic": "credential-access", "score": 100},
    {"techniqueID": "T1552.004", "tactic": "credential-access", "score": 100},
    {"techniqueID": "T1003.008", "tactic": "credential-access", "score": 100},
    {"techniqueID": "T1589.001", "tactic": "reconnaissance", "score": 100},
    {"techniqueID": "T1082", "tactic": "discovery", "score": 100},
    {"techniqueID": "T1083", "tactic": "discovery", "score": 100},
    {"techniqueID": "T1087.001", "tactic": "discovery", "score": 100},
    {"techniqueID": "T1018", "tactic": "discovery", "score": 100},
    {"techniqueID": "T1049", "tactic": "discovery", "score": 100},
    {"techniqueID": "T1057", "tactic": "discovery", "score": 100},
    {"techniqueID": "T1021.004", "tactic": "lateral-movement", "score": 100},
    {"techniqueID": "T1090.001", "tactic": "command-and-control", "score": 100},
    {"techniqueID": "T1563", "tactic": "lateral-movement", "score": 100},
    {"techniqueID": "T1005", "tactic": "collection", "score": 100},
    {"techniqueID": "T1039", "tactic": "collection", "score": 100},
    {"techniqueID": "T1071.001", "tactic": "command-and-control", "score": 100},
    {"techniqueID": "T1573.001", "tactic": "command-and-control", "score": 100},
    {"techniqueID": "T1095", "tactic": "command-and-control", "score": 100},
    {"techniqueID": "T1485", "tactic": "impact", "score": 75},
    {"techniqueID": "T1486", "tactic": "impact", "score": 75},
    {"techniqueID": "T1529", "tactic": "impact", "score": 75}
  ]
}
```

## 📥 How to Upload Layer
### Direct Import:

   - Save this file as .json
   - Go to the website above
   - Click "Open Existing Layer"
   - Select "Upload from local"
   - Choose your JSON file
   - Your heat map will load automatically!

---

## Recommendations

### Detection Engineering Priorities

1. **Implement comprehensive logging**
   - Enable auditd for command-line logging
   - Configure verbose logging for all services
   - Deploy centralized log management (SIEM)

2. **Deploy behavioral analytics**
   - Monitor for unusual authentication patterns
   - Detect lateral movement activities
   - Identify privilege escalation attempts

3. **Network security monitoring**
   - Deploy network IDS/IPS between segments
   - Implement network traffic analysis
   - Monitor for C2 communication patterns

4. **Endpoint detection and response**
   - Deploy EDR solution on all systems
   - Enable real-time threat detection
   - Implement automated response capabilities

5. **Threat hunting program**
   - Regular proactive threat hunting
   - Focus on TTPs identified in this assessment
   - Continuous improvement of detection rules

---

**Assessment Conducted By:** Senior Security Consultant  
**MITRE ATT&CK Mapping Date:** October 2025  
**Framework Version:** ATT&CK v14  
**Classification:** CONFIDENTIAL

*This mapping provides a comprehensive view of adversary techniques observed during the penetration test. Organizations should use this information to prioritize security control implementation and detection engineering efforts.* Network IDS signatures for port scans
- Log analysis of connection attempts to closed ports
- Behavioral analytics for reconnaissance patterns

---

#### T1087: Account Discovery
**Description:** Enumerated network shares and user accounts via SMB.

**Sub-technique:** T1087.002 (Domain Account)

**Tools Used:**
- smbclient

**Commands Executed:**
```bash
smbclient -L //10.50.100.10/ -N
smbclient //10.50.100.10/public -N
```

**Information Gathered:**
- Available SMB shares
- Accessible files and directories
- User credentials from share contents

**Detection Opportunities:**
- SMB access logging
- Failed authentication attempts
- Anonymous connection monitoring

---

#### T1592: Gather Victim Host Information
**Description:** Collected system information including OS version, kernel version, and installed software.

**Sub-technique:** T1592.002 (Software)

**Commands Executed:**
```bash
uname -a
cat /etc/os-release
sudo --version
```

**Information Gathered:**
- Ubuntu 14.04.3 LTS (webapps.corp.local)
- Ubuntu 24.04.3 LTS (vault.corp.internal)
- Sudo version 1.9.16p2
- Kernel version 6.8.0-39-generic

**Detection Opportunities:**
- Command execution monitoring
- File access auditing
- Unusual information gathering patterns

---

### Initial Access (TA0001)

**Objective:** Gain foothold within the target network

#### T1133: External Remote Services
**Description:** Exploited anonymous SMB access to retrieve credentials without authentication.

**Services Exploited:**
- Samba SMB (port 445)

**Access Method:**
- Anonymous/guest authentication

**Credentials Obtained:**
- Username: robert_admin
- Password: SecureP@ss2024

**Detection Opportunities:**
- Anonymous SMB connection logging
- Data exfiltration from shares
- Unusual file access patterns

---

#### T1078: Valid Accounts
**Description:** Used harvested credentials to authenticate to web application administrative panel.

**Sub-technique:** T1078.003 (Local Accounts)

**Accounts Compromised:**
- robert_admin (web application)
- admin_vault (SSH)
- root (MySQL)

**Authentication Methods:**
- Password-based authentication
- Credential reuse across systems

**Detection Opportunities:**
- Failed login attempt monitoring
- Geographic/temporal anomaly detection
- Privilege level changes

---
