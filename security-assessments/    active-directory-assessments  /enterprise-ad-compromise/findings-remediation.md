# Internal Network Penetration Test
## Vanguard Financial Services - Red Team Assessment
### Part 2 of 2

---

## 3. Findings & Vulnerabilities

### 3.1 Critical Vulnerabilities

#### [CRIT-001] Exposed Configuration File with Database Credentials
**CVSS Score:** 9.8 (Critical)  
**Affected Systems:** WEB-APP-01 (10.50.1.45)  
**CWE:** CWE-532 (Insertion of Sensitive Information into Log File)

**Description:**  
A backup configuration file (`config.php.bak`) was publicly accessible via the web application, containing plaintext database credentials. This file was discoverable through standard directory enumeration techniques.

**Evidence:**
```
URL: http://10.50.1.45/config.php.bak
Credentials exposed:
- Database User: webapp_user
- Database Password: WebApp2023!Secure
- Database Host: localhost
```

**Impact:**  
- Complete compromise of customer database (2,847 records)
- Access to personally identifiable information (PII)
- Credential reuse led to SSH access on application server
- Potential regulatory violations (GDPR, PCI-DSS)

**Remediation:**
1. **Immediate Actions:**
   - Remove all backup files from web-accessible directories
   - Implement `.htaccess` rules to deny access to `.bak, .old, .config, .txt` extensions
   - Store configuration files outside the web root directory
   - Use environment variables for sensitive configuration data

2. **Long-term Solutions:**
   - Implement secrets management solution (HashiCorp Vault, AWS Secrets Manager)
   - Rotate all exposed database credentials immediately
   - Review web server logs for unauthorized access to config.php.bak
   - Implement file integrity monitoring

**Verification:**
```bash
# Verify file removed
curl -I http://10.50.1.45/config.php.bak
# Expected: 404 Not Found

# Verify credentials rotated
mysql -h 10.50.1.45 -u webapp_user -p'WebApp2023!Secure'
# Expected: Access denied
```

---

#### [CRIT-002] Weak Password Policy Enables Credential Guessing
**CVSS Score:** 9.1 (Critical)  
**Affected Systems:** All domain systems  
**CWE:** CWE-521 (Weak Password Requirements)

**Description:**  
The current domain password policy allows 8-character passwords with basic complexity requirements. This enabled successful password spraying attacks, compromising multiple accounts using seasonal password patterns (Summer2024!, Spring2024!).

**Evidence:**
```
Current Password Policy:
- Minimum length: 8 characters
- Complexity: Enabled (but easily satisfied)
- Lockout threshold: 5 attempts
- Lockout duration: 30 minutes

Successfully compromised accounts:
- corp.vanguardfs.local\jthompson:Summer2024!
- corp.vanguardfs.local\sjenkins:Spring2024!
- corp.vanguardfs.local\sql_service:SQLSvc#2024!Backup

Attack success rate: 18% (2 of 11 tested users)
Time to compromise: 45 minutes
```

**Impact:**  
- Initial domain foothold achieved through weak passwords
- Complete domain compromise via privilege escalation chain
- High risk of credential-based attacks
- Password patterns predictable (Season+Year+!)

**Remediation:**
1. **Immediate Actions:**
   - Force password reset for all compromised accounts
   - Implement minimum 14-character password requirement
   - Deploy Azure AD Password Protection with custom banned password list
   - Add seasonal patterns to banned list (Summer, Spring, Fall, Winter + years)

2. **Short-term Actions:**
   - Enable multi-factor authentication (MFA) for all accounts
   - Implement passwordless authentication where possible (Windows Hello, FIDO2)
   - Configure fine-grained password policies for privileged accounts (20+ characters)
   - Deploy password breach monitoring

3. **Monitoring:**
   - Enable Event ID 4625 (failed logon) alerting
   - Monitor for password spray patterns (multiple users, single password)
   - Implement Smart Lockout in Azure AD Connect

**Verification:**
```powershell
# Check updated password policy
Get-ADDefaultDomainPasswordPolicy

# Verify Azure AD Password Protection
Get-AzureADPasswordProtectionPolicy

# Test weak password rejection
net user testuser "Summer2025!" /add /domain
# Expected: Password does not meet complexity requirements
```

---

#### [CRIT-003] SMB Signing Not Enforced
**CVSS Score:** 8.1 (High)  
**Affected Systems:** WKSTN-HR-05 (10.50.1.78), VFS-FS-01 (10.50.3.50)  
**CWE:** CWE-294 (Authentication Bypass by Capture-replay)

**Description:**  
SMB signing is not required on workstations and file server, allowing NTLM relay attacks. An attacker capturing credentials through LLMNR poisoning can relay them to systems without SMB signing enforcement.

**Evidence:**
```
SMB Signing Status Assessment:
┌──────────────┬──────────────┬─────────────────┬──────────────┐
│ Hostname     │ IP Address   │ SMB Signing     │ Exploitable  │
├──────────────┼──────────────┼─────────────────┼──────────────┤
│ WKSTN-HR-05  │ 10.50.1.78   │ Not Required    │ YES          │
│ VFS-FS-01    │ 10.50.3.50   │ Not Required    │ YES          │
│ VFS-DC-01    │ 10.50.2.10   │ Required        │ NO           │
│ VFS-DC-02    │ 10.50.2.11   │ Required        │ NO           │
└──────────────┴──────────────┴─────────────────┴──────────────┘

Successful relay attack demonstrated:
Source: WKSTN-HR-05 (10.50.1.78)
Target: VFS-FS-01 (10.50.3.50)
Result: SYSTEM-level access achieved
```

**Impact:**  
- Lateral movement without credential cracking
- Privilege escalation to SYSTEM on file server
- Bypass of authentication controls
- Silent attack (no failed logon events)

**Remediation:**
1. **Enable via Group Policy (Immediate):**
   ```
   Computer Configuration > Policies > Windows Settings > Security Settings > 
   Local Policies > Security Options
   
   Set the following policies:
   - "Microsoft network client: Digitally sign communications (always)" = Enabled
   - "Microsoft network server: Digitally sign communications (always)" = Enabled
   ```

2. **Verification Script:**
   ```powershell
   # Check SMB signing on all domain computers
   Get-ADComputer -Filter * | ForEach-Object {
       $computer = $_.Name
       $signing = Get-SmbServerConfiguration -CimSession $computer | 
                  Select-Object RequireSecuritySignature
       [PSCustomObject]@{
           Computer = $computer
           SMBSigningRequired = $signing.RequireSecuritySignature
       }
   }
   ```

3. **Additional Protections:**
   - Disable LLMNR and NetBIOS-NS (prevents capture phase)
   - Enable Extended Protection for Authentication
   - Implement network segmentation

---

#### [CRIT-004] Service Account with Weak Password and SPN
**CVSS Score:** 8.8 (High)  
**Affected Systems:** Domain Controllers, VFS-FS-01  
**CWE:** CWE-263 (Password Aging with Long Expiration)

**Description:**  
Service account `sql_service` has a weak password that was successfully cracked via Kerberoasting attack in under 5 minutes. The account has a registered Service Principal Name (SPN) making it vulnerable to offline password cracking.

**Evidence:**
```
Service Account Details:
Username: sql_service
SPN: MSSQLSvc/VFS-FS-01.corp.vanguardfs.local:1433
Password: SQLSvc#2024!Backup
Password Complexity: 19 characters (appears strong)
Cracked Time: 4 minutes 37 seconds
Wordlist: rockyou.txt with best64 rule

Group Memberships:
- Domain Users
- Server Operators (HIGH PRIVILEGE)
- Has WriteDacl on "Server Admins" group
```

**Attack Path:**
```
1. Kerberoasting (no special privileges required)
   ↓
2. Offline password cracking (SQLSvc#2024!Backup)
   ↓
3. WriteDacl permission abuse on "Server Admins"
   ↓
4. Add self to privileged group
   ↓
5. Lateral movement to all servers
```

**Impact:**  
- Service account compromise from any domain user
- Privilege escalation through ACL abuse
- Lateral movement to SQL servers and file servers
- No detection at credential compromise stage (offline attack)

**Remediation:**
1. **Immediate Actions:**
   - Reset sql_service password to 30+ random characters
   - Remove from Server Operators group (principle of least privilege)
   - Audit and remove WriteDacl permission on Server Admins

2. **Strategic Solution - Group Managed Service Accounts (gMSA):**
   ```powershell
   # Create gMSA for SQL Server
   New-ADServiceAccount -Name sql_gmsa -DNSHostName VFS-FS-01.corp.vanguardfs.local `
       -PrincipalsAllowedToRetrieveManagedPassword "VFS-FS-01$" `
       -ServicePrincipalNames "MSSQLSvc/VFS-FS-01.corp.vanguardfs.local:1433"
   
   # Install on SQL Server
   Install-ADServiceAccount -Identity sql_gmsa
   
   # Passwords managed automatically: 120 characters, rotated every 30 days
   ```

3. **Detection and Monitoring:**
   ```
   Enable Event ID 4769 monitoring for:
   - Ticket_Encryption_Type: 0x17 (RC4)
   - Service_Name: NOT *$
   - Account_Name: NOT *$
   
   Alert on multiple TGS requests for service accounts
   ```

---

### 3.2 High Severity Vulnerabilities

#### [HIGH-001] LLMNR and NetBIOS Name Service Poisoning
**CVSS Score:** 7.5 (High)  
**Affected Systems:** All Windows domain systems  
**CWE:** CWE-294 (Authentication Bypass by Capture-replay)

**Description:**  
Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS) are enabled across the domain, allowing adversaries to capture NTLMv2 hashes through poisoning attacks.

**Evidence:**
```
Responder Attack Results:
- Started: 2025-09-14 14:23:45
- First capture: 2025-09-14 14:35:12 (11 minutes)
- Total hashes captured: 3

Captured Credentials:
[+] [SMB] NTLMv2-SSP Client: 10.50.1.78
[+] [SMB] NTLMv2-SSP Username: VANGUARDFS\jthompson
[+] [SMB] NTLMv2-SSP Hash: jthompson::VANGUARDFS:1122334455667788:8A3D...

Hash Cracking Results:
- jthompson: Summer2024! (cracked in 8 minutes)
- mrodriguez: ITAdmin@2024! (cracked in 23 minutes)
```

**Impact:**  
- Passive credential harvesting
- No user interaction required beyond normal network operations
- Difficult to detect without specialized monitoring

**Remediation:**
1. **Disable LLMNR via Group Policy:**
   ```
   Computer Configuration > Administrative Templates > Network > DNS Client
   Policy: "Turn off multicast name resolution"
   Setting: Enabled
   ```

2. **Disable NetBIOS over TCP/IP:**
   ```powershell
   # Via Group Policy startup script
   $adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | 
               Where-Object {$_.IPEnabled -eq $true}
   foreach ($adapter in $adapters) {
       $adapter.SetTcpipNetbios(2) # 2 = Disable NetBIOS
   }
   ```

3. **Verification:**
   ```powershell
   # Check LLMNR status
   Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMulticast
   
   # Check NetBIOS status (Expected: TcpipNetbiosOptions = 2)
   Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" | 
       Select-Object Description, TcpipNetbiosOptions
   ```

---

#### [HIGH-002] Excessive Active Directory Permissions
**CVSS Score:** 7.8 (High)  
**Affected Systems:** Domain Controllers  
**CWE:** CWE-269 (Improper Privilege Management)

**Description:**  
Multiple low-privileged users and groups have excessive permissions through ACL misconfigurations and nested group memberships.

**BloodHound Findings:**

**Finding 1: WriteDacl on Privileged Groups**
```
User: sql_service
Permission: WriteDacl
Target: Server Admins (Group)
Impact: Can modify group membership and ACLs
```

**Finding 2: ForceChangePassword Permissions**
```
User: mrodriguez
Permission: ForceChangePassword  
Target: dadmin (Domain Admin)
Impact: Can reset Domain Admin password

Attack Path: mrodriguez → ForceChangePassword → dadmin → Domain Admins (1 hop)
```

**Finding 3: Nested Group Memberships**
```
jthompson → HR_Managers → GenericAll → IT_Administrators → Domain Admins
Chain of 3 hops leads to Domain Admin access
```

**Remediation:**
1. **Immediate ACL Cleanup:**
   ```powershell
   # Remove dangerous permissions
   Remove-DomainObjectAcl -PrincipalIdentity sql_service -Rights WriteDacl -TargetIdentity "Server Admins"
   Remove-DomainObjectAcl -PrincipalIdentity mrodriguez -Rights ForceChangePassword -TargetIdentity dadmin
   ```

2. **Implement AdminSDHolder Protection:**
   ```powershell
   # Ensure privileged accounts are protected
   $protectedUsers = @("dadmin","sql_service","backup_admin")
   foreach ($user in $protectedUsers) {
       Set-ADUser $user -Replace @{adminCount=1}
   }
   ```

3. **Regular ACL Auditing:**
   ```powershell
   # Monthly ACL review script
   $dangerous = @("GenericAll","WriteDacl","WriteOwner")
   Get-ADObject -Filter * -Properties nTSecurityDescriptor | ForEach-Object {
       # Audit dangerous permissions
   }
   ```

---

#### [HIGH-003] Local Administrator Password Reuse
**CVSS Score:** 7.8 (High)  
**Affected Systems:** WKSTN-HR-05, VFS-FS-01, multiple workstations  
**CWE:** CWE-257 (Storing Passwords in a Recoverable Format)

**Description:**  
Local administrator accounts share identical passwords across multiple systems.

**Evidence:**
```
Identical Local Admin NTLM Hash: 64f12cddaa88057e06a81b54e73b949b
Found on:
- WKSTN-HR-05 (10.50.1.78)
- VFS-FS-01 (10.50.3.50)
- 8 additional workstations

Password: Vanguard2024! (cracked)
Last Set: 2023-08-15 (over 1 year ago)
```

**Impact:**  
- Single password compromise affects multiple systems
- Enables rapid lateral movement
- Increases blast radius of any compromise

**Remediation:**
1. **Deploy Microsoft LAPS (Immediate):**
   ```powershell
   # Install LAPS
   Install-WindowsFeature RSAT-AD-PowerShell
   Import-Module AdmPwd.PS
   
   # Extend AD schema
   Update-AdmPwdADSchema
   
   # Configure GPO: 20 characters, 30-day rotation
   ```

2. **Verification:**
   ```powershell
   # Verify LAPS deployment
   Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd | 
       Where-Object {$_.ms-Mcs-AdmPwd -ne $null}
   ```

---

#### [HIGH-004] No Multi-Factor Authentication
**CVSS Score:** 7.3 (High)  
**Affected Systems:** All domain systems  
**CWE:** CWE-308 (Use of Single-factor Authentication)

**Description:**  
Domain administrator and service accounts do not require multi-factor authentication (MFA).

**Impact:**  
- Password compromise = full domain access
- Does not meet compliance requirements (PCI-DSS 8.3)

**Remediation:**
1. **Implement Azure MFA:**
   ```powershell
   Connect-MsolService
   $privilegedUsers = Get-MsolGroupMember -GroupObjectId (Get-MsolGroup | 
                      Where-Object {$_.DisplayName -eq "Domain Admins"}).ObjectId
   
   foreach ($user in $privilegedUsers) {
       $auth = New-Object -TypeName Microsoft.Online.Administration.StrongAuthenticationRequirement
       $auth.State = "Enabled"
       Set-MsolUser -UserPrincipalName $user.EmailAddress -StrongAuthenticationRequirements $auth
   }
   ```

2. **Smart Card Authentication (On-Premises):**
   ```powershell
   Get-ADGroupMember "Domain Admins" -Recursive | Get-ADUser | 
       ForEach-Object { Set-ADUser $_ -SmartcardLogonRequired $true }
   ```

---

### 3.3 Medium Severity Vulnerabilities

#### [MED-001] Outdated Apache Web Server
**CVSS Score:** 5.3 (Medium)  
**Affected Systems:** WEB-APP-01 (10.50.1.45)

**Description:** Apache 2.4.41 contains 15 known CVEs (6 High, 9 Medium severity)

**Remediation:**
```bash
sudo apt update
sudo apt upgrade apache2
apache2 -v  # Verify version 2.4.58 or later
```

---

#### [MED-002] RDP Without Network Level Authentication
**CVSS Score:** 5.9 (Medium)  
**Affected Systems:** WKSTN-HR-05

**Description:** NLA disabled, allowing credential brute-force attacks.

**Remediation:**
```powershell
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1
Restart-Service TermService -Force
```

---

#### [MED-003] Anonymous LDAP Binds Allowed
**CVSS Score:** 5.3 (Medium)  
**Affected Systems:** VFS-DC-01, VFS-DC-02

**Description:** Domain controllers allow anonymous LDAP queries.

**Remediation:**
```
Registry: HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters
Name: LDAPServerIntegrity
Type: DWORD
Value: 2 (Require signing)
```

---

### 3.4 Informational Findings

- **[INFO-001]** Unencrypted LDAP traffic (LDAPS not enforced)
- **[INFO-002]** No application whitelisting (AppLocker)
- **[INFO-003]** PowerShell logging disabled
- **[INFO-004]** Windows Defender disabled on workstation
- **[INFO-005]** Flat network topology (no segmentation)

---

## 4. Attack Chain Summary

### 4.1 Complete Compromise Path

```
PHASE 1: Initial Reconnaissance
└─> Network Scanning → Service Enumeration → 5 hosts identified

PHASE 2: Initial Access
└─> Web Application Enumeration
    └─> Config file exposure (config.php.bak)
        └─> Database credentials obtained
            └─> SSH access to WEB-APP-01

PHASE 3: Credential Harvesting
├─> LLMNR Poisoning → jthompson:Summer2024!
├─> ASREPRoasting → backup_admin:BackupPass2023!
├─> Password Spraying → sjenkins:Spring2024!
└─> Kerberoasting → sql_service:SQLSvc#2024!Backup

PHASE 4: Lateral Movement
└─> WinRM to WKSTN-HR-05
    └─> Memory credential dump
        └─> mrodriguez:ITAdmin@2024!
            └─> PSExec to VFS-FS-01

PHASE 5: Privilege Escalation
└─> BloodHound Analysis
    └─> ForceChangePassword path identified
        └─> dadmin password reset
            └─> Domain Admin access

PHASE 6: Domain Dominance
└─> DCSync Attack
    └─> All domain hashes extracted
        └─> krbtgt hash obtained
            └─> Golden Ticket capability

Total Time: 16 hours to Domain Admin
```

### 4.2 MITRE ATT&CK Mapping

| Tactic | Technique | ID | Observed |
|--------|-----------|-----|----------|
| **Reconnaissance** | Active Scanning | T1595 | ✓ Nmap |
| **Initial Access** | Exploit Public-Facing Application | T1190 | ✓ Config file |
| **Initial Access** | Valid Accounts | T1078.002 | ✓ Password spray |
| **Execution** | PowerShell | T1059.001 | ✓ Throughout |
| **Credential Access** | OS Credential Dumping: LSASS | T1003.001 | ✓ Mimikatz |
| **Credential Access** | Kerberoasting | T1558.003 | ✓ sql_service |
| **Credential Access** | AS-REP Roasting | T1558.004 | ✓ backup_admin |
| **Credential Access** | Brute Force: Password Spraying | T1110.003 | ✓ Multiple |
| **Credential Access** | LLMNR/NBT-NS Poisoning | T1557.001 | ✓ Responder |
| **Discovery** | Network Service Discovery | T1046 | ✓ Port scan |
| **Discovery** | Domain Trust Discovery | T1482 | ✓ BloodHound |
| **Lateral Movement** | Remote Services: WinRM | T1021.006 | ✓ Evil-WinRM |
| **Lateral Movement** | Remote Services: SMB | T1021.002 | ✓ PSExec |
| **Lateral Movement** | Pass the Hash | T1550.002 | ✓ Hash reuse |
| **Privilege Escalation** | Valid Accounts | T1078 | ✓ ACL abuse |
| **Collection** | Data from Network Shared Drive | T1039 | ✓ File server |

---

## 5. Remediation Strategy

### 5.1 Immediate Actions (0-7 Days) - CRITICAL

**Priority 1: Credential Security**
- [ ] Force password reset for all compromised accounts
- [ ] Reset all service account passwords (30+ random characters)
- [ ] Change krbtgt password twice (24-hour interval between changes)
- [ ] Enable account lockout (5 attempts, 30-minute lockout)

**Priority 2: Attack Surface Reduction**
- [ ] Remove config.php.bak from WEB-APP-01
- [ ] Enable SMB signing on all systems via Group Policy
- [ ] Disable LLMNR and NetBIOS-NS domain-wide
- [ ] Patch Apache to version 2.4.58 or later
- [ ] Enable NLA for all RDP endpoints

**Priority 3: Permission Remediation**
- [ ] Remove WriteDacl from sql_service on Server Admins
- [ ] Remove ForceChangePassword from mrodriguez on dadmin
- [ ] Remove GenericAll permissions identified in BloodHound
- [ ] Document all ACL changes

**Priority 4: Detection & Monitoring**
- [ ] Enable PowerShell script block logging (Event ID 4104)
- [ ] Configure alerts for Event ID 4625 (failed logons)
- [ ] Monitor for DCSync activity (Event ID 4662)
- [ ] Deploy Sysmon with quality configuration
- [ ] Enable Windows Event Forwarding

### 5.2 Short-Term Actions (1-4 Weeks) - HIGH PRIORITY

**Week 1-2: Authentication Hardening**
- [ ] Deploy Microsoft LAPS
- [ ] Implement MFA for all privileged accounts
- [ ] Configure Conditional Access policies
- [ ] Migrate service accounts to gMSA
- [ ] Implement smart card authentication for Domain Admins

**Week 2-3: Active Directory Security**
- [ ] Deploy BloodHound for ongoing monitoring
- [ ] Implement tiered administration model
- [ ] Enable AdminSDHolder protection
- [ ] Configure Protected Users security group
- [ ] Implement PAW (Privileged Access Workstation)

**Week 3-4: Network & Endpoint Security**
- [ ] Deploy EDR solution on all endpoints
- [ ] Implement application whitelisting (AppLocker)
- [ ] Enable Windows Defender real-time protection
- [ ] Configure Windows Firewall with Advanced Security
- [ ] Deploy network access control (NAC)

### 5.3 Medium-Term Actions (1-3 Months) - MEDIUM PRIORITY

**Month 1: Infrastructure Improvements**
- [ ] Implement network segmentation (VLANs)
  - Management VLAN (DCs, admin access)
  - Server VLAN (file servers, applications)
  - Workstation VLAN (user endpoints)
  - Guest VLAN (isolated, restricted)
- [ ] Deploy internal firewall rules between segments
- [ ] Implement jump server for administrative access
- [ ] Configure DHCP to disable NetBIOS

**Month 2: Security Monitoring & SIEM**
- [ ] Deploy SIEM solution (Splunk, Sentinel, Elastic)
- [ ] Configure log collection from all systems
- [ ] Develop use cases for common attack patterns
- [ ] Create incident response playbooks
- [ ] Establish SOC procedures

**Month 3: Compliance & Documentation**
- [ ] Document network architecture
- [ ] Create asset inventory
- [ ] Develop configuration baselines
- [ ] Implement configuration management
- [ ] Conduct tabletop exercise
- [ ] Perform compliance gap analysis

### 5.4 Long-Term Actions (3-12 Months)

- [ ] Zero Trust architecture implementation
- [ ] Regular penetration testing (quarterly)
- [ ] Purple team exercises
- [ ] Threat hunting program
- [ ] Security metrics dashboard
- [ ] Continuous improvement program
- [ ] Deploy deception technology
- [ ] Implement DLP solutions

### 5.5 Remediation Cost Estimate

| Category | Item | Cost | Timeline |
|----------|------|------|----------|
| **Immediate** | Password resets | $0 | Week 1 |
| | Group Policy configs | $0 | Week 1 |
| **Short-term** | LAPS | $0 | Week 2 |
| | MFA (Azure AD) | $6/user/month | Week 2-3 |
| | EDR solution | $50-100/endpoint/year | Week 3-4 |
| | Training | $5,000 | Month 1 |
| **Medium-term** | Network segmentation | $25,000-50,000 | Month 1-2 |
| | SIEM | $50,000-150,000 | Month 2-3 |
| | Consulting | $15,000 | Ongoing |
| **Long-term** | PAM solution | $100,000-250,000 | Quarter 2 |
| | Advanced tools | $75,000-200,000 | Q2-4 |
| | Annual pentests | $25,000-40,000 | Annual |
| **TOTAL (Year 1)** | | **$350,000-$900,000** | 12 months |

**ROI Justification:**
- Average data breach cost: $4.45M (IBM 2023)
- Average ransomware payment: $1.85M
- Regulatory fines (GDPR): Up to 4% annual revenue
- Investment provides 5-10x return

---

## 6. Detection & Monitoring Recommendations

### 6.1 Critical Detection Use Cases

#### Use Case 1: Password Spraying Detection
```
Data Source: Event ID 4625
Logic:
  - Same source IP
  - Multiple different usernames
  - Single password attempt per user
  - Within 30-minute window

SPL Query:
index=windows EventCode=4625 
| stats dc(user) as unique_users by src_ip 
| where unique_users > 5

Alert: 5+ failed attempts from single source
Response: Block source IP, notify SOC
```

#### Use Case 2: Kerberoasting Detection
```
Data Source: Event ID 4769
Logic:
  - Encryption type: RC4 (0x17)
  - Service name: NOT computer account
  - Multiple requests in short timeframe

SPL Query:
index=windows EventCode=4769 Ticket_Encryption_Type="0x17" 
| regex Service_Name!=".*\$" 
| stats count by src_user, Service_Name 
| where count > 3

Alert: 3+ service tickets within 5 minutes
Response: Investigate account, check for hash cracking
```

#### Use Case 3: DCSync Attack Detection
```
Data Source: Event ID 4662
Logic:
  - Directory Service Access
  - Replication GUIDs:
    - 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
    - 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
  - Account ≠ Domain Controller

SPL Query:
index=windows EventCode=4662 
  (Properties="*1131f6aa*" OR Properties="*1131f6ad*")
| search NOT Account_Name="*DC*"

Alert: ANY occurrence (CRITICAL)
Response: Immediate investigation, potential domain compromise
```

#### Use Case 4: Pass-the-Hash Detection
```
Data Source: Event ID 4624
Logic:
  - Logon Type: 3 (Network)
  - Logon Process: NtLmSsp
  - Same hash from multiple sources

SPL Query:
index=windows EventCode=4624 Logon_Type=3 Logon_Process=NtLmSsp 
| stats dc(src) as source_count by user, NTLM_hash 
| where source_count > 1

Alert: Same hash from 2+ sources
Response: Investigate lateral movement
```

### 6.2 Recommended Event Logging

**Authentication & Account Management:**
- 4624: Successful logon
- 4625: Failed logon
- 4648: Explicit credentials
- 4672: Special privileges assigned
- 4720: User account created
- 4732-4735: Group membership changes
- 4740: Account locked out

**Kerberos Events:**
- 4768: TGT requested
- 4769: Service ticket requested
- 4771: Pre-authentication failed

**Active Directory:**
- 4662: Operation on AD object
- 5136: Object modified
- 5137: Object created
- 5141: Object deleted

**PowerShell Logging:**
- 4103: Module logging
- 4104: Script block logging
- 4105: Script start
- 4106: Script stop

### 6.3 Sysmon Configuration

Deploy Sysmon with detection for:

```xml
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <!-- Event ID 1: Process Creation -->
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">sekurlsa</CommandLine>
      <CommandLine condition="contains">lsadump</CommandLine>
      <CommandLine condition="contains">-encodedcommand</CommandLine>
      <CommandLine condition="contains">invoke-expression</CommandLine>
      <Image condition="contains">psexec</Image>
    </ProcessCreate>
    
    <!-- Event ID 3: Network Connection -->
    <NetworkConnect onmatch="include">
      <DestinationPort condition="is">445</DestinationPort>
      <DestinationPort condition="is">5985</DestinationPort>
    </NetworkConnect>
    
    <!-- Event ID 10: Process Access (LSASS dumping) -->
    <ProcessAccess onmatch="include">
      <TargetImage condition="contains">lsass.exe</TargetImage>
    </ProcessAccess>
    
    <!-- Event ID 11: File Creation -->
    <FileCreate onmatch="include">
      <TargetFilename condition="contains">lsass</TargetFilename>
      <TargetFilename condition="contains">.dmp</TargetFilename>
    </FileCreate>
  </EventFiltering>
</Sysmon>
```

### 6.4 Alert Priority Matrix

| Alert Type | Severity | Response Time | Escalation |
|------------|----------|---------------|------------|
| DCSync Activity | CRITICAL | Immediate | CISO, IR Team |
| Golden Ticket Indicators | CRITICAL | Immediate | CISO, IR Team |
| Multiple Password Spray | HIGH | 15 minutes | SOC Lead |
| Kerberoasting Detected | HIGH | 30 minutes | SOC Lead |
| Pass-the-Hash | HIGH | 30 minutes | SOC Lead |
| LSASS Access | MEDIUM | 1 hour | SOC Analyst |
| Failed Logon Threshold | MEDIUM | 1 hour | SOC Analyst |
| Suspicious PowerShell | LOW | 4 hours | SOC Analyst |

---

## 7. Lessons Learned & Best Practices

### 7.1 Key Takeaways

**1. Defense in Depth is Critical**
- Single control failures led to complete compromise
- Layered security would have prevented or detected attacks
- MFA alone would have stopped password spray attacks

**2. Credential Security is Foundation**
- Weak passwords enabled initial access
- Credential reuse facilitated lateral movement
- Service account compromise led to privilege escalation
- **Lesson:** Invest heavily in credential management (LAPS, gMSA, MFA)

**3. Active Directory is the Crown Jewel**
- AD compromise = complete network compromise
- ACL misconfigurations create hidden escalation paths
- Regular BloodHound analysis essential
- **Lesson:** Treat AD security as top priority

**4. Visibility Enables Detection**
- Lack of logging prevented detection
- No alerts for common attack patterns
- Incident response impossible without data
- **Lesson:** Comprehensive logging and SIEM mandatory

**5. Configuration Matters**
- Exposed config file provided initial foothold
- Disabled security features enabled attacks
- Outdated software increases attack surface
- **Lesson:** Security hygiene prevents low-hanging fruit

### 7.2 Detection Opportunities Missed

**Initial Access Phase:**
- ✗ No web application firewall (WAF)
- ✗ No alerts on config file access
- ✗ SSH authentication not monitored
- ✓ **Should Have:** File integrity monitoring

**Credential Access Phase:**
- ✗ No LLMNR/NBT-NS traffic monitoring
- ✗ Failed logon attempts not aggregated
- ✗ Kerberoasting activity undetected
- ✓ **Should Have:** Authentication monitoring

**Lateral Movement Phase:**
- ✗ WinRM connections from workstations not flagged
- ✗ Pass-the-hash not detected
- ✗ Administrative access from standard users missed
- ✓ **Should Have:** Anomaly detection

**Privilege Escalation Phase:**
- ✗ BloodHound-like queries not detected
- ✗ ACL modifications not monitored
- ✗ Addition to privileged groups not alerted
- ✓ **Should Have:** AD change auditing

**Domain Compromise Phase:**
- ✗ DCSync activity completely missed (CRITICAL)
- ✗ Domain Admin logon not detected
- ✗ Credential dumping not identified
- ✓ **Should Have:** DC activity monitoring

### 7.3 Recommendations for Similar Organizations

**For Financial Services Sector:**

1. **Regulatory Compliance:**
   - PCI-DSS requires network segmentation
   - MFA mandatory for cardholder data access
   - Annual penetration testing required
   - Incident response procedures documented

2. **Industry-Specific Threats:**
   - Financial sector highly targeted
   - Ransomware and data exfiltration common
   - Insider threats significant concern
   - Third-party vendor risks

3. **Best Practices:**
   - Zero Trust architecture
   - Privileged Access Workstations (PAWs)
   - Regular security awareness training
   - Incident response retainer
   - Cyber insurance coverage

---

## 8. Conclusion

### 8.1 Executive Summary

**Overall Security Posture:** 🔴 **CRITICAL RISK**

This penetration test successfully demonstrated complete domain compromise within 16 hours. The assessment identified systemic issues across authentication, authorization, configuration management, and monitoring capabilities.

**Primary Security Gaps:**
1. Weak authentication controls (no MFA, weak passwords)
2. Excessive permissions (ACL misconfigurations)
3. Missing security configurations (SMB signing, LLMNR)
4. Insufficient logging and monitoring
5. Lack of network segmentation

**Business Impact:**
A real-world attacker with these capabilities could:
- Steal customer financial data (15,000+ records accessed)
- Deploy ransomware across entire domain
- Exfiltrate intellectual property
- Maintain persistent access for months/years
- Cause regulatory violations

**Estimated Financial Impact:** $3.5M - $10M
- Incident response: $500K - $1.5M
- Regulatory fines: $1M - $5M
- Customer notification: $500K - $1M
- Legal fees: $1M - $2M
- Reputational damage: Ongoing

### 8.2 Positive Findings

Despite vulnerabilities, several controls were properly implemented:

✓ Domain controllers have SMB signing enforced  
✓ DNS zone transfers properly restricted  
✓ No critical unpatched vulnerabilities on DCs  
✓ Firewall enabled on all Windows systems  
✓ Account lockout policy configured  
✓ Password complexity requirements enabled  
✓ LDAPS available (though not enforced)

### 8.3 Path Forward

**Immediate (Week 1):**
- Force password resets
- Enable SMB signing
- Remove exposed configuration files
- Disable LLMNR/NetBIOS-NS

**Short-term (Month 1):**
- Deploy LAPS
- Enable MFA for privileged accounts
- Fix critical ACL misconfigurations
- Enable comprehensive logging

**Strategic (Quarters 1-4):**
- SIEM deployment
- EDR on all endpoints
- Network segmentation
- Continuous monitoring and threat hunting

### 8.4 Final Recommendations

**For Leadership:**
1. Treat this as wake-up call, not compliance exercise
2. Allocate budget ($350K-900K Year 1)
3. Establish security as business enabler
4. Support security team with resources
5. Regular executive briefings

**For IT Security Team:**
1. Prioritize remediation based on risk
2. Implement "assume breach" mentality
3. Focus on detection as much as prevention
4. Document everything
5. Continuous improvement through testing

**For IT Operations:**
1. Security is everyone's responsibility
2. Follow secure configuration baselines
3. Patch management must be timely
4. Change management includes security review
5. Practice incident response procedures

---

## 9. Appendices

### Appendix A: Tools Used

**Reconnaissance & Enumeration:**
- Nmap 7.94 - Network scanning
- enum4linux - SMB enumeration
- ldapsearch - LDAP queries
- BloodHound 4.3.1 - AD attack paths
- Kerbrute - Kerberos enumeration

**Credential Access:**
- Responder 3.1.3.0 - LLMNR poisoning
- Impacket Suite - Windows protocols
- Hashcat 6.2.6 - Password cracking
- John the Ripper - Password cracking
- Mimikatz - Credential dumping

**Exploitation & Lateral Movement:**
- CrackMapExec 5.4.0 - Network pentesting
- Evil-WinRM - WinRM shell
- Impacket-psexec - Remote execution
- ntlmrelayx - SMB relay

**Post-Exploitation:**
- PowerView - AD enumeration
- PowerUp - Privilege escalation
- PrivescCheck - Enumeration
- WinPEAS - Windows enumeration

### Appendix B: Evidence Repository Structure

```
/evidence/
├── 01_reconnaissance/
│   ├── nmap_scans/
│   │   ├── ping_sweep.xml
│   │   ├── service_scan.xml
│   │   └── vuln_scan.xml
│   ├── dns_enumeration/
│   └── screenshots/
├── 02_enumeration/
│   ├── smb_shares/
│   ├── ldap_dumps/
│   ├── bloodhound_data/
│   │   ├── computers.json
│   │   ├── users.json
│   │   ├── groups.json
│   │   └── attack_paths.png
│   └── kerberos/
├── 03_credential_access/
│   ├── password_spraying/
│   │   └── successful_credentials.txt
│   ├── llmnr_poisoning/
│   │   ├── responder_log.txt
│   │   └── captured_hashes.txt
│   ├── kerberoasting/
│   │   └── cracked_passwords.txt
│   ├── asreproasting/
│   └── hash_cracking/
├── 04_lateral_movement/
│   ├── winrm_sessions/
│   ├── psexec_execution/
│   └── smb_relay/
├── 05_privilege_escalation/
│   ├── acl_abuse/
│   │   └── bloodhound_paths.png
│   └── domain_privesc/
├── 06_domain_dominance/
│   ├── dcsync/
│   │   └── domain_hashes.txt
│   └── golden_ticket_demo/
└── 07_screenshots/
    ├── critical_findings/
    ├── exploitation/
    └── proof_of_compromise/
```

### Appendix C: Detailed Timeline

**Day 1: September 14, 2025**

| Time | Activity | Result |
|------|----------|--------|
| 09:00 | Engagement kickoff | Scope confirmed |
| 09:15 | Network discovery | 5 hosts identified |
| 10:30 | Port scanning | Services enumerated |
| 11:00 | SMB enumeration | Signing not required |
| 12:30 | Config file discovered | DB credentials |
| 13:00 | SSH access obtained | WEB-APP-01 shell |
| 14:00 | Password spray | 2 accounts compromised |
| 14:35 | LLMNR hash captured | jthompson hash |
| 15:08 | Password cracked | Summer2024! |
| 16:30 | Kerberoasting | sql_service ticket |
| 18:00 | Lateral to file server | VFS-FS-01 access |
| 20:00 | BloodHound collection | Domain data gathered |
| 22:30 | Password reset attack | dadmin compromised |
| 23:30 | DC access obtained | VFS-DC-02 shell |

**Day 2: September 15, 2025**

| Time | Activity | Result |
|------|----------|--------|
| 00:00 | DCSync attack | All hashes extracted |
| 01:00 | Golden ticket demo | Created (not deployed) |
| 08:00 | Documentation begins | Report writing |
| 16:00 | Engagement complete | Final report |

**Total Time to Domain Admin:** 16 hours

### Appendix D: Compliance Mapping

**PCI-DSS v4.0 Findings:**

| Requirement | Status | Finding |
|-------------|--------|---------|
| 1.2.1 Network segmentation | ❌ FAIL | Flat network |
| 2.2.1 Secure configurations | ❌ FAIL | Multiple misconfigs |
| 8.2.1 Strong authentication | ❌ FAIL | Weak passwords, no MFA |
| 8.2.3 MFA for admin | ❌ FAIL | No MFA |
| 10.2 Audit logging | ⚠️ PARTIAL | Incomplete logs |
| 11.3 Penetration testing | ✅ PASS | This assessment |

**Compliance Grade: D- (35% compliant)**

**NIST CSF v1.1 Maturity:**
- Identify: Level 2/5 (Partial)
- Protect: Level 1/5 (Initial)
- Detect: Level 1/5 (Initial)
- Respond: Level 1/5 (Initial)
- Recover: Level 1/5 (Initial)

**Overall Maturity:** Tier 1 (Partial)  
**Target:** Tier 3 (Repeatable) within 18 months

### Appendix E: Remediation Validation Checklist

**Phase 1: Critical Vulnerabilities (Week 1)**

```
☐ Config File Removed
  ├─ Verify: curl returns 404
  └─ Verify: .htaccess blocks sensitive extensions

☐ Passwords Reset
  ├─ jthompson, sjenkins, dadmin, sql_service, backup_admin
  ├─ Old passwords no longer work
  └─ New passwords meet 14+ character requirement

☐ SMB Signing Enabled
  ├─ GPO deployed to all systems
  ├─ WKSTN-HR-05 requires signing
  ├─ VFS-FS-01 requires signing
  └─ Test: SMB relay attack fails

☐ LLMNR/NetBIOS Disabled
  ├─ GPO deployed domain-wide
  ├─ All systems disabled
  └─ Test: Responder captures nothing

☐ ACL Permissions Fixed
  ├─ WriteDacl removed from sql_service
  ├─ ForceChangePassword removed from mrodriguez
  └─ BloodHound shows no paths to Domain Admin
```

**Phase 2: High Priority (Weeks 2-4)**

```
☐ LAPS Deployed
  ├─ Schema extended
  ├─ GPO configured
  ├─ Unique passwords on all systems
  └─ Test: Password rotation working

☐ MFA Enabled
  ├─ Domain Admins have MFA
  ├─ Service accounts protected
  └─ Test: Authentication requires second factor

☐ Service Accounts Secured
  ├─ Migrated to gMSA
  ├─ 30+ character passwords
  └─ Test: Kerberoasting yields uncrackable hashes

☐ Logging Enabled
  ├─ PowerShell script block logging
  ├─ Sysmon deployed
  ├─ Event forwarding configured
  └─ Logs collecting centrally
```

**Final Validation: Re-Test**
```
☐ Password spray: BLOCKED
☐ LLMNR poisoning: NO HASHES
☐ Kerberoasting: UNCRACKABLE
☐ SMB relay: FAILED
☐ ACL abuse: NO PATHS
☐ DCSync: DETECTED AND ALERTED
☐ Overall: Domain compromise NOT achievable
```

### Appendix F: References

**Industry Standards:**
- NIST SP 800-115: Technical Guide to Information Security Testing
- NIST SP 800-53: Security and Privacy Controls
- PTES: Penetration Testing Execution Standard
- MITRE ATT&CK Framework for Enterprise
- CIS Controls v8

**Active Directory Security:**
- Microsoft: Active Directory Security Best Practices
- Microsoft: Securing Privileged Access
- adsecurity.org - Sean Metcalf's research
- BloodHound: Six Degrees of Domain Admin - SpecterOps

**Detection and Response:**
- ThreatHunter-Playbook - Roberto Rodriguez
- Sigma Rules - Generic signature format for SIEM
- Sysmon Configuration - SwiftOnSecurity

**Tools Documentation:**
- Impacket: github.com/SecureAuthCorp/impacket
- BloodHound: github.com/BloodHoundAD/BloodHound
- CrackMapExec: github.com/byt3bl33d3r/CrackMapExec

---

## 10. Document Control & Distribution

### Version History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 0.1 | 2025-09-15 | Vitor Anjos | Initial draft |
| 1.0 | 2025-09-19 | Vitor Anjos | Final report |

### Distribution List

**Internal:**
- Chief Information Security Officer (CISO)
- Chief Information Officer (CIO)
- IT Security Team Lead
- Compliance Officer

### Confidentiality Statement

This document contains security information about simulated systems created for training and professional development. All systems tested were owned/controlled by the assessor. No unauthorized access occurred.

**Classification:** CONFIDENTIAL - Portfolio Demonstration  
**Handling:** For career development purposes only

### Report Integrity

**SHA-256 Hash:** `[Generate after PDF creation]`

To verify:
```bash
sha256sum Vanguard_Pentest_Report_Part2.pdf
```

### Contact Information

**Lead Penetration Tester:**  
**Name:** Vitor Anjos  
**Certifications:** eCPPTv3   
**GitHub:** [Vitor-D-Anjos](https://github.com/Vitor-D-Anjos)  
**Portfolio:** [offensive-security](https://github.com/Vitor-D-Anjos/offensive-security-portfolio)

---

## Acknowledgments

This assessment was made possible by the excellent work of the information security community who develop and maintain open-source tools:

- The Impacket development team
- BloodHound developers at SpecterOps
- The CrackMapExec community
- Offensive Security for penetration testing training
- The MITRE ATT&CK framework team

**Lab Environment:** This assessment was conducted in a purpose-built penetration testing laboratory designed to simulate enterprise Active Directory environments for security training and skills development.

---

**END OF REPORT - PART 2 OF 2**

---

## Quick Reference Card (For Interviews)

### Key Metrics
- **Duration:** 48-hour assessment
- **Time to Domain Admin:** 16 hours
- **Critical Findings:** 4
- **High Findings:** 4
- **Domain Compromise:** Yes (100%)

### Most Impactful Findings
1. 🔴 Weak password policy → Initial access
2. 🔴 Config file exposure → Database access
3. 🔴 SMB signing disabled → Lateral movement
4. 🔴 ACL misconfigurations → Privilege escalation

### Attack Chain (30-Second Summary)
```
Config file → SSH → LLMNR → Domain user → 
Kerberoasting → ACL abuse → Domain Admin → 
DCSync → Full compromise
```

### Skills Demonstrated
✓ Network reconnaissance & enumeration  
✓ Active Directory security assessment  
✓ Windows & Linux exploitation  
✓ Credential attacks (Kerberoasting, ASREPRoast, spraying)  
✓ Lateral movement techniques  
✓ BloodHound attack path analysis  
✓ DCSync and domain compromise  
✓ Professional report writing  
✓ Business risk communication  

### Tools Proficiency
✓ Nmap, Impacket, BloodHound  
✓ Responder, Hashcat, Mimikatz  
✓ CrackMapExec, Evil-WinRM  
✓ PowerView, LDAP tools  
✓ Custom scripting (bash/PowerShell)  

---

**Report Prepared By:** Vitor Anjos, eCCPT 
**Date:** September 19, 2025  
**Document ID:** VFS-PENTEST-2025-09-PART2  
**Classification:** CONFIDENTIAL - Portfolio Demonstration

*This penetration test report represents professional security assessment capabilities developed through training, certification, and hands-on practice in controlled laboratory environments.*
