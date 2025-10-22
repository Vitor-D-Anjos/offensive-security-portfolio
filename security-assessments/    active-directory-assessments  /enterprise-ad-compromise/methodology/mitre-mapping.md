# MITRE ATT&CK Mapping

## Reconnaissance
- T1595: Active Scanning (Nmap)

## Initial Access  
- T1190: Exploit Public-Facing Application
- T1078: Valid Accounts

## Execution
- T1059: Command and Scripting Interpreter

## Persistence
- T1136: Create Account

## Privilege Escalation
- T1068: Exploitation for Privilege Escalation

## Defense Evasion
- T1562: Impair Defenses

## Credential Access
- T1003: OS Credential Dumping
- T1558: Steal or Forge Kerberos Tickets

## Discovery
- T1018: Remote System Discovery
- T1087: Account Discovery

## Lateral Movement
- T1021: Remote Services
- T1570: Lateral Tool Transfer

## Collection
- T1005: Data from Local System

## Command and Control
- T1071: Application Layer Protocol



________________________
__________________________



# 🎯 MITRE ATT&CK Mapping

<div align="center">

[![Back to Methodology](https://img.shields.io/badge/←_Back_to-Methodology-blue?style=for-the-badge)](./README.md)
[![View MITRE ATT&CK](https://img.shields.io/badge/Visit-MITRE_ATT&CK_Website-red?style=for-the-badge)](https://attack.mitre.org/)

</div>

---

## Overview

This document maps all observed techniques from the Enterprise Active Directory Compromise assessment to the **MITRE ATT&CK Framework for Enterprise**. This mapping enables blue teams to understand adversary behavior patterns and improve detection capabilities.

**MITRE ATT&CK Version:** v14  
**Assessment Date:** September 2025  
**Techniques Observed:** 15 unique techniques across 7 tactics

---

## 📊 Tactics Overview

<table>
  <tr>
    <th>Tactic</th>
    <th>Techniques</th>
    <th>Coverage</th>
  </tr>
  <tr>
    <td>Reconnaissance</td>
    <td>1</td>
    <td>🟢 Observed</td>
  </tr>
  <tr>
    <td>Initial Access</td>
    <td>2</td>
    <td>🟢 Observed</td>
  </tr>
  <tr>
    <td>Execution</td>
    <td>1</td>
    <td>🟢 Observed</td>
  </tr>
  <tr>
    <td>Credential Access</td>
    <td>6</td>
    <td>🟢 Observed</td>
  </tr>
  <tr>
    <td>Discovery</td>
    <td>2</td>
    <td>🟢 Observed</td>
  </tr>
  <tr>
    <td>Lateral Movement</td>
    <td>3</td>
    <td>🟢 Observed</td>
  </tr>
  <tr>
    <td>Collection</td>
    <td>1</td>
    <td>🟢 Observed</td>
  </tr>
</table>

---

## 🔍 Detailed Technique Mapping

### Tactic: Reconnaissance

#### T1595 - Active Scanning

**Sub-Technique:** T1595.001 - Scanning IP Blocks

**Description:** Adversary conducted network scanning to identify live hosts and services.

**Tools Used:**
- Nmap
- Netdiscover
- ARP-scan

**Commands Executed:**
```bash
nmap -sn 10.50.0.0/22
nmap -sV -sC -p- 10.50.1.45,10.50.1.78,10.50.2.10,10.50.2.11,10.50.3.50
```

**Detection Opportunities:**
- Network IDS signatures for port scanning
- Unusual ICMP traffic patterns
- Multiple connection attempts to various ports

**Defenses:**
- Network segmentation
- IDS/IPS deployment
- Rate limiting on connection attempts

---

### Tactic: Initial Access

#### T1190 - Exploit Public-Facing Application

**Description:** Exposed configuration backup file led to credential disclosure and initial access.

**Details:**
- URL: `http://10.50.1.45/config.php.bak`
- Credentials obtained: `webapp_user:WebApp2023!Secure`
- Led to SSH access on WEB-APP-01

**Impact:** Critical - Initial foothold established

**Detection Opportunities:**
- Web access logs monitoring for `.bak` file requests
- File integrity monitoring on web directories
- Unusual authentication patterns

**Defenses:**
- Remove backup files from web-accessible directories
- Implement `.htaccess` rules
- Web Application Firewall (WAF)

---

#### T1078.002 - Valid Accounts: Domain Accounts

**Description:** Password spraying attacks compromised legitimate domain user accounts.

**Compromised Accounts:**
- `jthompson:Summer2024!`
- `sjenkins:Spring2024!`

**Attack Method:** Password spraying with seasonal patterns

**Detection Opportunities:**
- Event ID 4625 (failed logons) aggregation
- Multiple failed authentications across different accounts
- Authentication from unusual locations

**Defenses:**
- Implement MFA
- Account lockout policies
- Stronger password requirements (14+ characters)
- Azure AD Password Protection

---

### Tactic: Execution

#### T1059.001 - Command and Scripting Interpreter: PowerShell

**Description:** PowerShell used throughout the engagement for enumeration, exploitation, and post-exploitation.

**Usage Examples:**
- Active Directory enumeration
- Credential harvesting (Mimikatz)
- Lateral movement (PSRemoting)
- File operations

**Detection Opportunities:**
- PowerShell script block logging (Event ID 4104)
- Module logging (Event ID 4103)
- Suspicious command patterns
- Encoded command execution

**Defenses:**
- Enable comprehensive PowerShell logging
- Constrained Language Mode
- Application whitelisting (AppLocker)
- Monitor for suspicious cmdlets

---

### Tactic: Credential Access

#### T1557.001 - Man-in-the-Middle: LLMNR/NBT-NS Poisoning

**Description:** Responder used to poison LLMNR/NBT-NS queries and capture NTLMv2 hashes.

**Tools Used:**
- Responder 3.1.3.0

**Captured Credentials:**
- `jthompson::VANGUARDFS:...:8A3D...`
- Cracked to: `Summer2024!`

**Detection Opportunities:**
- Monitor for unusual LLMNR/NBT-NS traffic
- Network anomaly detection
- Multiple authentication attempts from single source

**Defenses:**
- Disable LLMNR via Group Policy
- Disable NetBIOS over TCP/IP
- Network segmentation
- SMB signing enforcement

---

#### T1110.003 - Brute Force: Password Spraying

**Description:** Systematic password spraying against domain accounts with common patterns.

**Attack Pattern:**
- Single password tested against multiple accounts
- Rate-limited to avoid account lockouts (3 attempts per 30 min)
- Seasonal password patterns (Summer2024!, Spring2024!)

**Success Rate:** 18% (2 of 11 users)

**Detection Opportunities:**
- Event ID 4625 pattern analysis
- Same source IP, multiple users, single password
- Smart Lockout in Azure AD

**Defenses:**
- Implement account lockout policies
- Deploy MFA
- Azure AD Password Protection
- Smart Lockout

---

#### T1558.004 - Steal or Forge Kerberos Tickets: AS-REP Roasting

**Description:** Targeted users with "Do not require Kerberos preauthentication" enabled.

**Compromised Account:**
- `backup_admin` (password: `BackupPass2023!`)

**Tools Used:**
- Impacket GetNPUsers

**Commands:**
```bash
impacket-GetNPUsers corp.vanguardfs.local/ -dc-ip 10.50.2.11 -usersfile users.txt
```

**Detection Opportunities:**
- Event ID 4768 with unusual patterns
- Kerberos authentication without pre-auth
- Accounts with "Do not require pre-auth" attribute

**Defenses:**
- Audit accounts with pre-auth disabled
- Enforce Kerberos pre-authentication
- Monitor for AS-REP requests

---

#### T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting

**Description:** Requested service tickets for accounts with SPNs to perform offline password cracking.

**Compromised Account:**
- `sql_service` (MSSQLSvc/VFS-FS-01:1433)
- Password: `SQLSvc#2024!Backup`
- Cracked in: 4 minutes 37 seconds

**Tools Used:**
- Impacket GetUserSPNs
- Hashcat

**Detection Opportunities:**
- Event ID 4769 with RC4 encryption (0x17)
- Service name NOT ending in '$'
- Multiple TGS requests in short timeframe

**Defenses:**
- Migrate to Group Managed Service Accounts (gMSA)
- Use strong passwords (30+ random characters)
- Enforce AES encryption for Kerberos
- Monitor Event ID 4769

---

#### T1003.001 - OS Credential Dumping: LSASS Memory

**Description:** Extracted credentials from LSASS memory on compromised workstation.

**Tools Used:**
- Mimikatz
- pypykatz

**Credentials Obtained:**
- `mrodriguez:ITAdmin@2024!`
- Multiple NTLM hashes

**Detection Opportunities:**
- Sysmon Event ID 10 (ProcessAccess) targeting lsass.exe
- Mimikatz string signatures
- Unusual process accessing LSASS
- Event ID 4656 (handle to LSASS)

**Defenses:**
- Credential Guard
- Protected Process Light (PPL) for LSASS
- EDR solutions
- Restricted Admin mode for RDP

---

#### T1003.006 - OS Credential Dumping: DCSync

**Description:** Used DCSync attack to extract all domain credentials including krbtgt hash.

**Tools Used:**
- Impacket secretsdump

**Commands:**
```bash
impacket-secretsdump -just-dc-ntlm corp.vanguardfs.local/dadmin:password@10.50.2.11
```

**Extracted:**
- All domain user NTLM hashes
- krbtgt hash (golden ticket capability)
- Computer account hashes

**Detection Opportunities:**
- Event ID 4662 with replication GUIDs
  - 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 (DS-Replication-Get-Changes)
  - 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 (DS-Replication-Get-Changes-All)
- Account performing replication NOT a DC
- CRITICAL alert priority

**Defenses:**
- Monitor Event ID 4662
- Restrict DCSync permissions
- AdminSDHolder protection
- Alert on any non-DC DCSync attempts

---

### Tactic: Discovery

#### T1046 - Network Service Discovery

**Description:** Port scanning and service enumeration to map network and identify attack vectors.

**Tools Used:**
- Nmap
- CrackMapExec

**Information Gathered:**
- Open ports and services
- Service versions
- Operating systems
- SMB signing status

**Detection Opportunities:**
- Multiple connection attempts to various ports
- Network flow analysis
- IDS signatures

**Defenses:**
- Network segmentation
- Firewall rules
- IDS/IPS deployment

---

#### T1482 - Domain Trust Discovery

**Description:** BloodHound used to enumerate domain structure, relationships, and attack paths.

**Tools Used:**
- BloodHound
- bloodhound-python

**Information Gathered:**
- User and group relationships
- ACL permissions
- Attack paths to Domain Admins
- Trust relationships

**Detection Opportunities:**
- LDAP queries for all domain objects
- Unusual volume of LDAP queries
- SharpHound execution detection

**Defenses:**
- Monitor LDAP query patterns
- Limit LDAP query permissions
- Deploy deception (honey accounts)
- Regular BloodHound analysis by defenders

---

### Tactic: Lateral Movement

#### T1021.006 - Remote Services: Windows Remote Management

**Description:** WinRM (Evil-WinRM) used for lateral movement and command execution.

**Target Systems:**
- WKSTN-HR-05 (10.50.1.78)
- VFS-FS-01 (10.50.3.50)

**Tools Used:**
- Evil-WinRM

**Detection Opportunities:**
- Event ID 4624 (Logon Type 3 - Network)
- WinRM connections from unusual sources
- Port 5985/5986 connections
- PowerShell remoting activity

**Defenses:**
- Restrict WinRM access
- Implement JEA (Just Enough Administration)
- Monitor WinRM usage
- Network segmentation

---

#### T1021.002 - Remote Services: SMB/Windows Admin Shares

**Description:** PSExec and similar tools used for remote code execution via SMB.

**Tools Used:**
- Impacket psexec
- Impacket smbexec

**Detection Opportunities:**
- Event ID 4624 (Logon Type 3)
- Service creation (Event ID 7045)
- Named pipe creation
- ADMIN$ share access

**Defenses:**
- Disable ADMIN$ share where not needed
- Restrict administrative access
- Monitor service creation
- EDR detection

---

#### T1550.002 - Use Alternate Authentication Material: Pass the Hash

**Description:** NTLM hashes used directly for authentication without knowing plaintext passwords.

**Tools Used:**
- CrackMapExec
- Impacket suite

**Example:**
```bash
crackmapexec smb 10.50.3.50 -u mrodriguez -H a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
```

**Detection Opportunities:**
- Event ID 4624 with Logon Type 3
- NTLMv1/NTLMv2 authentication
- Same hash used from multiple sources
- Unusual authentication patterns

**Defenses:**
- Enforce NTLMv2 and disable NTLMv1
- Implement Kerberos where possible
- Credential Guard
- LAPS for local admin passwords

---

### Tactic: Collection

#### T1039 - Data from Network Shared Drive

**Description:** Accessed file server shares to enumerate and collect sensitive data.

**Shares Accessed:**
- IT_Admin
- Finance$
- HR_Confidential
- Backups

**Data Discovered:**
- Credential files (backup_credentials.txt)
- Financial documents
- Employee PII (1,247 records)
- Customer data (15,000+ records)

**Detection Opportunities:**
- Unusual share access patterns
- Mass file access
- Access to sensitive shares from non-standard accounts
- Event ID 5140 (network share access)

**Defenses:**
- Implement least privilege access
- File access auditing
- DLP solutions
- Honeypot files and shares

---

## 🛡️ Detection Summary

### Critical Detections

**Highest Priority (Implement Immediately):**

1. **DCSync Detection**
   - Event ID 4662 with replication GUIDs
   - Any non-DC account performing replication
   - **CRITICAL ALERT**

2. **LSASS Memory Access**
   - Sysmon Event ID 10 targeting lsass.exe
   - Mimikatz signatures
   - **HIGH ALERT**

3. **Kerberoasting**
   - Event ID 4769 with RC4 encryption
   - Service name NOT ending in '$'
   - Multiple requests in short period
   - **HIGH ALERT**

4. **Pass-the-Hash**
   - Event ID 4624, Logon Type 3, NTLMv2
   - Same hash from multiple sources
   - **MEDIUM ALERT**

---

### SIEM Correlation Rules

**Rule 1: Password Spraying**
```
index=windows EventCode=4625
| stats dc(user) as unique_users by src_ip
| where unique_users > 5
```

**Rule 2: Kerberoasting**
```
index=windows EventCode=4769 Ticket_Encryption_Type="0x17"
| regex Service_Name!=".*\$"
| stats count by src_user
| where count > 3
```

**Rule 3: DCSync**
```
index=windows EventCode=4662
(Properties="*1131f6aa*" OR Properties="*1131f6ad*")
| search NOT Account_Name="*DC*"
```

---

## 📈 ATT&CK Navigator Layer

**Layer File:** Available for import into ATT&CK Navigator

```json
{
  "name": "Enterprise AD Compromise - Vanguard Assessment",
  "versions": {
    "attack": "14",
    "navigator": "4.9.1",
    "layer": "4.5"
  },
  "domain": "enterprise-attack",
  "description": "Techniques observed during the Enterprise Active Directory Compromise assessment",
  "techniques": [
    {"techniqueID": "T1595.001", "enabled": true, "color": "#e60d0d"},
    {"techniqueID": "T1190", "enabled": true, "color": "#e60d0d"},
    {"techniqueID": "T1078.002", "enabled": true, "color": "#e60d0d"},
    {"techniqueID": "T1059.001", "enabled": true, "color": "#ffa500"},
    {"techniqueID": "T1557.001", "enabled": true, "color": "#e60d0d"},
    {"techniqueID": "T1110.003", "enabled": true, "color": "#e60d0d"},
    {"techniqueID": "T1558.004", "enabled": true, "color": "#e60d0d"},
    {"techniqueID": "T1558.003", "enabled": true, "color": "#e60d0d"},
    {"techniqueID": "T1003.001", "enabled": true, "color": "#e60d0d"},
    {"techniqueID": "T1003.006", "enabled": true, "color": "#ff0000"},
    {"techniqueID": "T1046", "enabled": true, "color": "#ffa500"},
    {"techniqueID": "T1482", "enabled": true, "color": "#ffa500"},
    {"techniqueID": "T1021.006", "enabled": true, "color": "#e60d0d"},
    {"techniqueID": "T1021.002", "enabled": true, "color": "#e60d0d"},
    {"techniqueID": "T1550.002", "enabled": true, "color": "#e60d0d"},
    {"techniqueID": "T1039", "enabled": true, "color": "#ffa500"}
  ]
}
```

**Color Legend:**
- 🔴 Red (#ff0000): Critical impact techniques (DCSync)
- 🔴 Dark Red (#e60d0d): High impact techniques
- 🟠 Orange (#ffa500): Medium impact techniques

---

## 🎯 Kill Chain Mapping

### Cyber Kill Chain to ATT&CK

| Kill Chain Phase | ATT&CK Tactic | Techniques Used |
|------------------|---------------|-----------------|
| Reconnaissance | Reconnaissance | T1595.001 |
| Weaponization | Resource Development | N/A (Used existing tools) |
| Delivery | Initial Access | T1190, T1078.002 |
| Exploitation | Execution | T1059.001 |
| Installation | Persistence | (Documented, not deployed) |
| Command & Control | C2 | (Interactive sessions via tools) |
| Actions on Objectives | Credential Access, Lateral Movement, Collection | T1003.001, T1003.006, T1021.006, T1039 |

---

## 📚 Defenses by Tactic

### Reconnaissance Defenses
- Network segmentation
- IDS/IPS deployment
- Rate limiting
- Honeypots and deception

### Initial Access Defenses
- Remove backup files from web directories
- Web Application Firewall (WAF)
- Strong authentication (MFA)
- Password policies (14+ characters)
- Azure AD Password Protection

### Execution Defenses
- PowerShell logging (script block, module, transcription)
- Constrained Language Mode
- Application whitelisting (AppLocker)
- JEA (Just Enough Administration)

### Credential Access Defenses
- Disable LLMNR and NetBIOS-NS
- Implement MFA on all accounts
- Migrate to Group Managed Service Accounts (gMSA)
- Strong password requirements (20+ chars for service accounts)
- Credential Guard
- Protected Process Light for LSASS
- Monitor Event IDs: 4625, 4768, 4769, 4662

### Discovery Defenses
- LDAP query monitoring
- Limit anonymous LDAP binds
- Regular BloodHound analysis by defenders
- Deception (honey accounts)

### Lateral Movement Defenses
- Network segmentation
- Restrict WinRM and RDP access
- LAPS for local administrator passwords
- Disable NTLM where possible
- Enforce Kerberos authentication
- Monitor service creation (Event ID 7045)

### Collection Defenses
- Least privilege access to shares
- File access auditing (Event ID 5140)
- Data Loss Prevention (DLP)
- Sensitive file encryption
- Honeypot files

---

## 🔬 Technique Details

### Most Impactful Techniques (Ranked)

1. **T1003.006 (DCSync)** - CRITICAL
   - Complete domain compromise
   - All credentials extracted
   - Enables golden ticket attacks
   - **Priority 1 Detection**

2. **T1558.003 (Kerberoasting)** - HIGH
   - Service account compromise
   - Led to privilege escalation
   - Offline attack (no detection at time of attack)
   - **Priority 2 Detection**

3. **T1078.002 (Valid Accounts)** - HIGH
   - Initial domain foothold
   - Enabled further attacks
   - Password spraying successful
   - **Priority 2 Detection**

4. **T1003.001 (LSASS Dumping)** - HIGH
   - Additional credential harvest
   - Enabled lateral movement
   - IT administrator credentials obtained
   - **Priority 2 Detection**

5. **T1557.001 (LLMNR Poisoning)** - MEDIUM
   - Passive credential capture
   - First domain credentials obtained
   - Difficult to detect without specialized monitoring
   - **Priority 3 Detection**

---

## 📊 Coverage Analysis

### ATT&CK Matrix Coverage

**Tactics Observed:** 7 of 14 (50%)
- ✅ Reconnaissance
- ✅ Initial Access
- ✅ Execution
- ❌ Persistence (documented, not deployed)
- ❌ Privilege Escalation (achieved via other tactics)
- ✅ Credential Access
- ❌ Defense Evasion (minimal focus)
- ✅ Discovery
- ✅ Lateral Movement
- ✅ Collection
- ❌ Command and Control (interactive only)
- ❌ Exfiltration (proof-of-concept only)
- ❌ Impact (out of scope)

### Typical APT Comparison

This assessment demonstrates techniques commonly observed in:
- **APT29 (Cozy Bear)** - Credential dumping, lateral movement
- **APT28 (Fancy Bear)** - Kerberoasting, Pass-the-Hash
- **FIN7** - Network reconnaissance, credential theft
- **Wizard Spider** - Lateral movement via WinRM/RDP

---

## 🛠️ Blue Team Recommendations

### Detection Engineering Priorities

**Week 1-2: Critical Detections**
1. Implement DCSync detection (Event ID 4662)
2. Enable LSASS access monitoring (Sysmon Event ID 10)
3. Deploy Kerberoasting detection (Event ID 4769)
4. Configure password spray detection (Event ID 4625 aggregation)

**Week 3-4: High Priority Detections**
1. Pass-the-Hash detection (Event ID 4624 analysis)
2. LLMNR/NBT-NS traffic monitoring
3. Unusual LDAP query detection
4. Service creation monitoring (Event ID 7045)

**Month 2: Enhanced Monitoring**
1. Deploy Sysmon with quality configuration
2. Implement SIEM correlation rules
3. Create detection dashboards
4. Establish alert tuning process

### Threat Hunting Opportunities

**Hunt 1: Kerberoasting Activity**
```
Look for Event ID 4769 with:
- Encryption Type: 0x17 (RC4)
- Service Name NOT ending in '
- Multiple requests from same account
```

**Hunt 2: Credential Dumping**
```
Search for:
- Process access to lsass.exe
- Unusual processes with debug privileges
- Memory dump files (.dmp) in unusual locations
```

**Hunt 3: Lateral Movement Patterns**
```
Analyze:
- WinRM connections between workstations
- Administrative logons from non-PAW systems
- SMB connections with admin share access
```

---

## 📖 Additional Resources

### MITRE ATT&CK Resources
- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [ATT&CK for Enterprise](https://attack.mitre.org/matrices/enterprise/)
- [ATT&CK Evaluations](https://attackevals.mitre-engenuity.org/)

### Detection Resources
- [Sigma Rules Repository](https://github.com/SigmaHQ/sigma)
- [Splunk Security Content](https://research.splunk.com/)
- [Elastic Detection Rules](https://www.elastic.co/guide/en/security/current/prebuilt-rules.html)
- [ThreatHunter-Playbook](https://threathunterplaybook.com/)

### Active Directory Security
- [AD Security - Sean Metcalf](https://adsecurity.org/)
- [Harmj0y Blog](http://blog.harmj0y.net/)
- [SpecterOps Blog](https://posts.specterops.io/)

---

## 📫 Navigation

<div align="center">

[![Back to Methodology](https://img.shields.io/badge/←-Methodology-blue?style=for-the-badge)](./README.md)
[![Project Home](https://img.shields.io/badge/🏠-Project_Home-green?style=for-the-badge)](../README.md)
[![Technical Report](https://img.shields.io/badge/→-Technical_Assessment-orange?style=for-the-badge)](../technical-assessment.md)

</div>

---

**Summary:** This assessment demonstrated 15 unique ATT&CK techniques across 7 tactics, resulting in complete domain compromise. The techniques observed are consistent with real-world APT groups and ransomware operators, highlighting the critical importance of implementing detection and prevention controls.

---

*This MITRE ATT&CK mapping enables blue teams to understand the attack progression and implement appropriate detections and defenses.*

**Last Updated:** October 2025  
**MITRE ATT&CK Version:** v14

