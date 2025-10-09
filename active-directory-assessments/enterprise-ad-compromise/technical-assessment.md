# Technical Assessment

## Executive Summary
This document details the technical execution of the penetration test, following the PTES methodology across six phases.

## Phase 1: Reconnaissance & Discovery
### Network Scanning

Host discovery

nmap -sn 10.50.0.0/22
Service enumeration

nmap -sV -sC -A 10.50.1.45,10.50.1.78,10.50.2.10,10.50.2.11,10.50.3.50

text
**Key Findings:**  
- 5 primary hosts identified  
- Multiple Windows domain services detected  
- SMB signing not required on workstations and file server  

## Phase 2: Initial Access
### Web Application Analysis  
Discovered exposed configuration file at [http://10.50.1.45/config.php.bak](http://10.50.1.45/config.php.bak) containing database credentials.  
**Credentials Obtained:**  
- Database User: webapp_user  
- Database Password: WebApp2023!Secure  

### SSH Access  
Successfully authenticated to WEB-APP-01 using discovered credentials.

## Phase 3: Credential Access
### LLMNR Poisoning  
Deployed Responder, captured NTLMv2 hash within 12 minutes:  

[SMB] NTLMv2-SSP Client: 10.50.1.78
[SMB] NTLMv2-SSP Username: VANGUARDFS\jthompson

text

### Password Spraying  
Successful compromises:  
- jthompson:Summer2024!  
- sjenkins:Spring2024!

### Kerberoasting  
Cracked service account sql_service in 4 minutes 37 seconds.

## Phase 4: Lateral Movement
### SMB Relay Attacks  
Exploited missing SMB signing to relay credentials and gain SYSTEM access on VFS-FS-01.

### WinRM Access  
Used compromised credentials to access multiple systems via Evil-WinRM.

## Phase 5: Privilege Escalation
### BloodHound Analysis  
Identified privilege escalation path:  

jthompson → HR_Managers → GenericAll → IT_Administrators → Domain Admins

text

### ACL Abuse  
- sql_service had WriteDacl on "Server Admins" group  
- mrodriguez had ForceChangePassword on Domain Admin dadmin  

## Phase 6: Domain Dominance
### DCSync Attack  
Extracted all domain hashes using Domain Admin privileges:  

impacket-secretsdump -just-dc-ntlm corp.vanguardfs.local/dadmin@10.50.2.11

text

### Golden Ticket Capability  
Demonstrated golden ticket creation using extracted krbtgt hash.

## MITRE ATT&CK Mapping

| Tactic            | Technique                  | ID        |
|-------------------|----------------------------|-----------|
| Initial Access    | Exploit Public-Facing Application | T1190     |
| Credential Access | OS Credential Dumping       | T1003.001 |
| Lateral Movement  | Remote Services: SMB        | T1021.002 |
| Privilege Escalation | Abuse Elevation Control Mechanism | T1548     |

---

### **Findings & Remediation Strategy**

## Critical Vulnerabilities

### [CRIT-001] Exposed Configuration File  
**CVSS:** 9.8 | **Systems:** WEB-APP-01  
**Description:** Backup configuration file publicly accessible containing plaintext database credentials.  
**Impact:** Complete database compromise, credential reuse leading to system access.  
**Remediation:**  
- Remove backup files from web directories  
- Store configurations outside web root  
- Implement secrets management  
- Rotate exposed credentials  

### [CRIT-002] Weak Password Policy  
**CVSS:** 9.1 | **Systems:** Domain-wide  
**Description:** 8-character minimum allows predictable seasonal passwords.  
**Impact:** Successful password spraying compromised multiple accounts.  
**Remediation:**  
- Implement 14-character minimum  
- Deploy Azure AD Password Protection  
- Enable MFA for all accounts  

### [CRIT-003] SMB Signing Not Enforced  
**CVSS:** 8.1 | **Systems:** WKSTN-HR-05, VFS-FS-01  
**Description:** SMB signing not required, enabling NTLM relay attacks.  
**Impact:** Lateral movement without credential cracking.  
**Remediation:**  
- Enable SMB signing via Group Policy  
- Disable LLMNR and NetBIOS-NS  

### [CRIT-004] Service Account Weaknesses  
**CVSS:** 8.8 | **Systems:** Domain Controllers  
**Description:** Service account with weak, crackable password and excessive permissions.  
**Impact:** Privilege escalation through ACL abuse.  
**Remediation:**  
- Migrate to Group Managed Service Accounts (gMSA)  
- Implement 30+ character passwords  
- Remove excessive permissions  

## Remediation Timeline

### Immediate (Week 1)  
- Force password resets for compromised accounts  
- Enable SMB signing domain-wide  
- Remove exposed configuration files  
- Disable LLMNR and NetBIOS-NS  

### Short-term (Month 1)  
- Deploy Microsoft LAPS  
- Implement MFA for privileged accounts  
- Fix ACL misconfigurations  
- Enable comprehensive logging  

### Long-term (Year 1)  
- Network segmentation  
- EDR deployment  
- SIEM implementation  
- Regular penetration testing  

## Business Impact Analysis  
**Estimated Breach Cost:** $3.5M - $10M  
- Incident response: $500K - $1.5M  
- Regulatory fines: $1M - $5M  
- Reputational damage: Ongoing  
