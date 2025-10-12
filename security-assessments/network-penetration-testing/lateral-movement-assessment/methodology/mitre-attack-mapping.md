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

## 🗺️ Attack Flow Mapping

```mermaid
graph TD
    A[T1595.002: Vulnerability Scanning] --> B[T1110.001: Password Guessing]
    B --> C[T1078.003: Valid Accounts Compromise]
    C --> D[T1087.002: Account Discovery]
    D --> E[T1003.008: Credential Dumping]
    E --> F[T1021.004: SSH Lateral Movement]
    F --> G[T1548.003: Sudo Privilege Escalation]
    G --> H[T1550.002: Pass the Hash]
    H --> I[TA0008: Domain Compromise]

## 🗺️ Attack Flow Summary

1. T1595.002: Vulnerability Scanning → Network scanning
2. T1110.001: Password Guessing → SSH brute force attack
3. T1078.003: Valid Accounts Compromise → Weak account access
4. T1087.002: Account Discovery → Harvesting domain accounts
5. T1003.008: Credential Dumping → Extract password hashes
6. T1021.004: SSH Lateral Movement → Moving laterally via SSH
7. T1548.003: Sudo Privilege Escalation → Escalating with sudo rights
8. T1550.002: Pass the Hash → Using hashed credentials
9. TA0008: Domain Compromise → Achieved full domain control

🎯 Technique Details
T1110.001 - Password Guessing

Description: Systematic attempt to guess passwords via SSH service
Evidence:
bash

hydra -L userlist -P passlist ssh://web-server-01.internal.corp

T1021.004 - SSH Lateral Movement

Description: Use of SSH for moving between systems with compromised credentials
Evidence:
bash

ssh jsmith@app-server-01.internal.corp

T1548.003 - Sudo Privilege Escalation

Description: Abuse of sudo permissions to execute malicious scripts as root
Evidence:
bash

sudo -l
# (root) NOPASSWD: /opt/scripts/backup.sh

T1550.002 - Pass the Hash

Description: Use of password hashes for authentication instead of plaintext passwords
Evidence:
bash

pth-winexe -U administrator//[hash] //dc-01.internal.corp cmd

📊 Detection Recommendations
T1110.001 Detection
bash

# SIEM query for SSH brute force detection
source="ssh_logs" failed password | stats count by src_ip | where count > 10

T1550.002 Detection
powershell

# Windows Event ID for Pass-the-Hash
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624; LogonType=9}

T1021.004 Detection
bash

# SSH lateral movement monitoring
grep "Accepted password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c

🔄 MITRE ATT&CK Navigator Layer

A complete MITRE ATT&CK Navigator layer is available for this engagement, showing:

    Techniques used during testing

    Detection coverage gaps

    Mitigation recommendations

    Tactical progression mapping

📈 Strategic Insights

This engagement demonstrates how attackers can chain multiple techniques to achieve domain compromise. The mapping shows:

    Initial Access: Relies on weak credentials (T1110.001)

    Discovery: Extensive internal reconnaissance (TA0007)

    Lateral Movement: Multiple techniques for horizontal spread (TA0008)

    Privilege Escalation: Systematic privilege elevation (TA0004)

    Objective Achievement: Domain control (T1550.002)

🛡️ Mitigation Alignment

Each technique maps to specific MITRE D3FEND countermeasures:

    D3-PSA - Privileged Account Management

    D3-LBP - Login Baseline Profile

    D3-NTA - Network Traffic Analysis

    D3-CSP - Configuration Standards Enforcement

MITRE ATT&CK Mapping - For Defensive Planning
