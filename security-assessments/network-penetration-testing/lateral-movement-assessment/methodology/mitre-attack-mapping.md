# MITRE ATT&CK Framework Mapping

## 📋 Engagement Technique Mapping

This engagement demonstrated multiple techniques from the MITRE ATT&CK Enterprise framework, showing real-world adversarial tradecraft aligned with the documented lateral movement assessment.

## 🔥 Techniques Demonstrated

### TA0043: Reconnaissance
| Technique ID | Technique Name | Evidence |
|--------------|----------------|----------|
| T1595.002 | Active Scanning: Vulnerability Scanning | Network scanning with nmap (`nmap -sn 192.168.78.0/24`) |
| T1592.002 | Gather Victim Host Information: Software | Service version detection (`nmap -sS -sV`) |

### TA0042: Resource Development
| Technique ID | Technique Name | Evidence |
|--------------|----------------|----------|
| T1588.002 | Obtain Capabilities: Tool | Hydra for SSH brute force, Impacket for pass-the-hash |

### TA0001: Initial Access
| Technique ID | Technique Name | Evidence |
|--------------|----------------|----------|
| T1110.001 | Brute Force: Password Guessing | SSH credential attack against svc_webapp account |
| T1078.003 | Valid Accounts | SSH access as svc_webapp with weak credentials |

### TA0007: Discovery
| Technique ID | Technique Name | Evidence |
|--------------|----------------|----------|
| T1087.002 | Account Discovery: Domain Account | Database credential harvesting (jsmith credentials) |
| T1069.002 | Permission Groups Discovery: Domain Groups | Local user privilege enumeration (`sudo -l`) |
| T1018 | Remote System Discovery | Network host enumeration (`nmap` scans) |
| T1083 | File and Directory Discovery | Configuration file searching (`find / -name "*.config"`) |

### TA0008: Lateral Movement
| Technique ID | Technique Name | Evidence |
|--------------|----------------|----------|
| T1021.002 | Remote Services: SMB/Windows Admin Shares | SMB share access testing |
| T1021.004 | Remote Services: SSH | SSH lateral movement with reused credentials |
| T1550.002 | Use Alternate Authentication Material: Pass the Hash | PTH to domain controller with extracted hashes |

### TA0004: Privilege Escalation
| Technique ID | Technique Name | Evidence |
|--------------|----------------|----------|
| T1548.003 | Abuse Elevation Control Mechanism: Sudo | Backup script privilege escalation |
| T1055 | Process Injection | Script manipulation for root access |

### TA0006: Credential Access
| Technique ID | Technique Name | Evidence |
|--------------|----------------|----------|
| T1003.008 | OS Credential Dumping: /etc/passwd and /etc/shadow | Linux hash extraction (`cat /etc/shadow`) |
| T1552.001 | Unsecured Credentials: Credentials in Files | Database config file access (`/var/www/html/config/database.php`) |

### TA0009: Collection
| Technique ID | Technique Name | Evidence |
|--------------|----------------|----------|
| T1005 | Data from Local System | Local file system enumeration |
| T1213 | Data from Information Repositories | Database information collection (customer_data table) |

### TA0011: Command and Control
| Technique ID | Technique Name | Evidence |
|--------------|----------------|----------|
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP-based communication for tool transfer |
| T1571 | Non-Standard Port | SSH connections on standard port 22 |

🗺️ Attack Flow Summary
🔍 Phase 1: Reconnaissance & Initial Access

T1595.002 → T1110.001 → T1078.003
text

Network Scanning → Password Guessing → Valid Account Compromise
    ↓
nmap discovery → Hydra SSH attack → svc_webapp access

📁 Phase 2: Discovery & Credential Harvesting

T1083 → T1552.001
text

File Discovery → Credentials in Files
    ↓
Config file search → Database credentials found

🔄 Phase 3: Lateral Movement

T1021.004 → T1548.003
text

SSH Lateral Movement → Sudo Privilege Escalation
    ↓
jsmith@app-server-01 → Backup script exploitation

🗝️ Phase 4: Privilege Escalation & Credential Access

T1003.008 → T1550.002
text

Credential Dumping → Pass the Hash
    ↓
/etc/shadow extraction → Domain controller access

👑 Phase 5: Domain Compromise

TA0008
text

Domain Compromise Achieved
    ↓
Full enterprise control established

📊 Attack Chain Progression
Phase	MITRE Technique	Action	Evidence
1. Recon	T1595.002	Network scanning	nmap -sn 192.168.78.0/24
1. Initial Access	T1110.001	SSH brute force	hydra against svc_webapp
1. Access	T1078.003	Valid account use	SSH as svc_webapp
2. Discovery	T1083	File enumeration	find / -name "*.config"
2. Credentials	T1552.001	Config file access	Database credentials harvested
3. Lateral Move	T1021.004	SSH credential reuse	Access as jsmith
3. Privilege Esc	T1548.003	Sudo abuse	Backup script manipulation
4. Credential Access	T1003.008	Hash extraction	/etc/shadow dump
4. Authentication	T1550.002	Pass-the-hash	Domain controller access
5. Final Objective	TA0008	Domain compromise	Full enterprise control
🎯 Technique Chain Sequence
text

1. T1595.002 (Scanning)
   ↓
2. T1110.001 (Brute Force)
   ↓  
3. T1078.003 (Valid Accounts)
   ↓
4. T1083 (File Discovery)
   ↓
5. T1552.001 (Credential Harvesting)
   ↓
6. T1021.004 (Lateral Movement)
   ↓
7. T1548.003 (Privilege Escalation)
   ↓
8. T1003.008 (Credential Dumping)
   ↓
9. T1550.002 (Pass-the-Hash)
   ↓
10. TA0008 (Domain Compromise)

text

## 🎯 Key Technique Details

### T1110.001 - Password Guessing

**Description:** Systematic attempt to guess passwords via SSH service  
**Evidence:**

hydra -L userlist -P passlist ssh://web-server-01.internal.corp
Success: svc_webapp:Summer2024!

text

### T1021.004 - SSH Lateral Movement

**Description:** Use of SSH for moving between systems with compromised credentials  
**Evidence:**

ssh jsmith@app-server-01.internal.corp
Password: Welcome123! (reused from database)

text

### T1548.003 - Sudo Privilege Escalation

**Description:** Abuse of sudo permissions to execute malicious scripts as root  
**Evidence:**

sudo -l
(root) NOPASSWD: /opt/scripts/backup.sh

text

### T1550.002 - Pass the Hash

**Description:** Use of password hashes for authentication instead of plaintext passwords  
**Evidence:**

pth-winexe -U administrator//[hash] //dc-01.internal.corp cmd

text

### T1552.001 - Unsecured Credentials

**Description:** Discovery of credentials stored in configuration files  
**Evidence:**

cat /var/www/html/config/database.php
db_user = 'app_dbuser', db_pass = 'DbAdmin123!'

text

## 🛡️ Detection Recommendations

### T1110.001 Detection - SSH Brute Force

SIEM query for SSH brute force detection

source="ssh_logs" failed password | stats count by src_ip | where count > 10

text

### T1550.002 Detection - Pass-the-Hash

Windows Event ID for Pass-the-Hash detection

Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624; LogonType=9}

text

### T1021.004 Detection - SSH Lateral Movement

SSH lateral movement monitoring

grep "Accepted password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c

text

### T1552.001 Detection - Credential Exposure

File integrity monitoring for config files

find /var/www -name "*.php" -exec grep -l "password|passwd|pwd" {} ;

text

## 📈 Strategic Insights

This engagement demonstrates a realistic attack chain from initial compromise to domain control:

- Initial Access → Weak SSH credentials (T1110.001)  
- Discovery → Configuration file analysis (T1083, T1552.001)  
- Lateral Movement → Credential reuse via SSH (T1021.004)  
- Privilege Escalation → Sudo rights abuse (T1548.003)  
- Credential Access → Hash extraction (T1003.008)  
- Domain Compromise → Pass-the-hash (T1550.002)  

## 🔄 MITRE ATT&CK Framework Integration

This assessment demonstrates comprehensive alignment with MITRE ATT&CK, mapping each exploitation technique to specific framework identifiers. The attack chain visualization shows how techniques were chained to achieve domain compromise.

**Framework Coverage:**

- 8 MITRE ATT&CK Tactics  
- 15+ Individual Techniques  
- Full attack lifecycle mapping  
- Detection and mitigation alignment  

## 🛡️ Mitigation Alignment

Each technique maps to specific MITRE D3FEND countermeasures:

- D3-PSA - Privileged Account Management (T1078.003, T1548.003)  
- D3-LBP - Login Baseline Profile (T1110.001, T1021.004)  
- D3-NTA - Network Traffic Analysis (T1595.002, T1021.004)  
- D3-CSP - Configuration Standards Enforcement (T1552.001)  
- D3-SCA - System Configuration Analysis (T1003.008, T1548.003)  

## 📊 Attack Chain Statistics

| Metric                  | Count     |
|-------------------------|-----------|
| Tactics Covered         | 8 of 14   |
| Techniques Used        | 15+       |
| Initial Access Vectors | 2         |
| Privilege Escalation Methods | 2    |
| Lateral Movement Techniques | 3     |





-----
----



# MITRE ATT&CK Framework Mapping

## 📋 Engagement Technique Mapping

This engagement demonstrated multiple techniques from the MITRE ATT&CK Enterprise framework, showing real-world adversarial tradecraft.

## 🔥 Techniques Demonstrated

### TA0043: Reconnaissance
| Technique ID | Technique Name | Evidence |
|--------------|----------------|----------|
| T1595.002 | Active Scanning: Vulnerability Scanning | Network scanning with nmap |
| T1592.002 | Gather Victim Host Information: Software | Service version detection |

### TA0042: Resource Development
| Technique ID | Technique Name | Evidence |
|--------------|----------------|----------|
| T1588.002 | Obtain Capabilities: Tool | Hydra, Impacket suite usage |

### TA0001: Initial Access
| Technique ID | Technique Name | Evidence |
|--------------|----------------|----------|
| T1110.001 | Brute Force: Password Guessing | SSH credential attack against svc_webapp |
| T1078.003 | Valid Accounts: Local Accounts | Weak service account compromise |

### TA0007: Discovery
| Technique ID | Technique Name | Evidence |
|--------------|----------------|----------|
| T1087.002 | Account Discovery: Domain Account | Database credential harvesting |
| T1069.002 | Permission Groups Discovery: Domain Groups | Domain group enumeration |
| T1018 | Remote System Discovery | Network host enumeration |

### TA0008: Lateral Movement
| Technique ID | Technique Name | Evidence |
|--------------|----------------|----------|
| T1021.001 | Remote Services: Remote Desktop Protocol | RDP access attempts |
| T1021.002 | Remote Services: SMB/Windows Admin Shares | SMB share access |
| T1021.004 | Remote Services: SSH | SSH lateral movement |
| T1550.002 | Use Alternate Authentication Material: Pass the Hash | PTH to domain controller |

### TA0004: Privilege Escalation
| Technique ID | Technique Name | Evidence |
|--------------|----------------|----------|
| T1548.003 | Abuse Elevation Control Mechanism: Sudo | Backup script privilege escalation |
| T1068 | Exploitation for Privilege Escalation | Script manipulation for root access |

### TA0006: Credential Access
| Technique ID | Technique Name | Evidence |
|--------------|----------------|----------|
| T1003.008 | OS Credential Dumping: /etc/passwd and /etc/shadow | Linux hash extraction |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | Database config file access |

### TA0009: Collection
| Technique ID | Technique Name | Evidence |
|--------------|----------------|----------|
| T1005 | Data from Local System | Local file system enumeration |
| T1213 | Data from Information Repositories | Database information collection |

### TA0011: Command and Control
| Technique ID | Technique Name | Evidence |
|--------------|----------------|----------|
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP-based communication |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | SSH encrypted tunnels |

## 🗺️ Attack Flow Summary

1. **T1595.002**: Vulnerability Scanning → Network discovery & service enumeration
2. **T1110.001**: Password Guessing → SSH brute force against svc_webapp
3. **T1078.003**: Valid Accounts → Initial access via weak service credentials  
4. **T1083**: File Discovery → Configuration file enumeration
5. **T1552.001**: Credentials in Files → Database credentials harvested
6. **T1021.004**: SSH Lateral Movement → App server access with jsmith credentials
7. **T1548.003**: Sudo Privilege Escalation → Backup script exploitation for root access
8. **T1003.008**: Credential Dumping → Hash extraction from /etc/shadow
9. **T1550.002**: Pass the Hash → Domain controller compromise
10. **TA0008**: Domain Compromise → Full enterprise control achieved

## 🎯 Technique Details

### T1110.001 - Password Guessing

**Description:** Systematic attempt to guess passwords via SSH service  
**Evidence:**

hydra -L userlist -P passlist ssh://web-server-01.internal.corp

text

### T1021.004 - SSH Lateral Movement

**Description:** Use of SSH for moving between systems with compromised credentials  
**Evidence:**

ssh jsmith@app-server-01.internal.corp

text

### T1548.003 - Sudo Privilege Escalation

**Description:** Abuse of sudo permissions to execute malicious scripts as root  
**Evidence:**

sudo -l
(root) NOPASSWD: /opt/scripts/backup.sh

text

### T1550.002 - Pass the Hash

**Description:** Use of password hashes for authentication instead of plaintext passwords  
**Evidence:**

pth-winexe -U administrator//[hash] //dc-01.internal.corp cmd

text

## 📊 Detection Recommendations

### T1110.001 Detection

SIEM query for SSH brute force detection

source="ssh_logs" failed password | stats count by src_ip | where count > 10

text

### T1550.002 Detection

Windows Event ID for Pass-the-Hash

Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624; LogonType=9}

text

### T1021.004 Detection

SSH lateral movement monitoring

grep "Accepted password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c

text

## 🔄 MITRE ATT&CK Framework Alignment

This engagement demonstrates alignment with the MITRE ATT&CK framework through:
- Technique mapping to specific ATT&CK IDs
- Attack chain progression visualization  
- Detection and mitigation recommendations
- Enterprise attack surface coverage

## 📈 Strategic Insights

This engagement demonstrates how attackers can chain multiple techniques to achieve domain compromise. The mapping shows:

- Initial Access: Relies on weak credentials (T1110.001)  
- Discovery: Extensive internal reconnaissance (TA0007)  
- Lateral Movement: Multiple techniques for horizontal spread (TA0008)  
- Privilege Escalation: Systematic privilege elevation (TA0004)  
- Objective Achievement: Domain control (T1550.002)  

## 🛡️ Mitigation Alignment

Each technique maps to specific MITRE D3FEND countermeasures:

- D3-PSA - Privileged Account Management  
- D3-LBP - Login Baseline Profile  
- D3-NTA - Network Traffic Analysis  
- D3-CSP - Configuration Standards Enforcement  

---

MITRE ATT&CK Mapping - For Defensive Planning
