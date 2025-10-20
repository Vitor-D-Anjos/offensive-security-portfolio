# Testing Methodology

## Framework Compliance
This assessment follows industry-standard penetration testing frameworks:

### PTES (Penetration Testing Execution Standard)
1. Pre-engagement Interactions
2. Intelligence Gathering
3. Threat Modeling
4. Vulnerability Analysis
5. Exploitation
6. Post-Exploitation
7. Reporting

### MITRE ATT&CK Framework
Mapped all techniques to MITRE ATT&CK for Enterprise.

### NIST SP 800-115
Compliant with technical security testing guide.

## Testing Phases

### Phase 1: Planning & Preparation
- Scope definition
- Rules of engagement
- Communication protocols

### Phase 2: Discovery
- Network reconnaissance
- Service enumeration
- Application mapping

### Phase 3: Attack
- Vulnerability exploitation
- Privilege escalation
- Lateral movement

### Phase 4: Reporting
- Findings documentation
- Risk assessment
- Remediation guidance





_____________
__________________


# 📋 Penetration Testing Methodology

<div align="center">

[![Back to Project](https://img.shields.io/badge/←_Back_to_Project-Cover_Sheet-blue?style=for-the-badge)](../cover-sheet.md)
[![MITRE ATT&CK Mapping](https://img.shields.io/badge/View-MITRE_Mapping-red?style=for-the-badge)](./mitre-mapping.md)

</div>

---

## Overview

This assessment followed industry-standard penetration testing frameworks and methodologies to ensure comprehensive coverage, professional execution, and actionable results.

---

## 🎯 Frameworks & Standards Applied

### 1. PTES (Penetration Testing Execution Standard)

The **Penetration Testing Execution Standard** provided the overall structure for this engagement:

**Pre-Engagement Interactions**
- Scope definition and rules of engagement
- Asset inventory and target identification
- Communication protocols established

**Intelligence Gathering**
- Passive reconnaissance (OSINT)
- Active reconnaissance (network scanning)
- Service enumeration and fingerprinting

**Threat Modeling**
- Attack surface analysis
- Potential attack path identification
- Risk assessment and prioritization

**Vulnerability Analysis**
- Automated scanning
- Manual testing and validation
- Configuration review

**Exploitation**
- Initial access vector execution
- Privilege escalation
- Lateral movement

**Post-Exploitation**
- Credential harvesting
- Persistence mechanisms (documented, not deployed)
- Data access demonstration

**Reporting**
- Technical documentation
- Executive summary
- Remediation guidance

🔗 **Reference:** [PTES Technical Guidelines](http://www.pentest-standard.org/index.php/PTES_Technical_Guidelines)

---

### 2. MITRE ATT&CK Framework

The **MITRE ATT&CK** framework was used to map observed techniques to adversary tactics, techniques, and procedures (TTPs):

**Tactics Observed:**
- Reconnaissance
- Initial Access
- Execution
- Persistence
- Credential Access
- Discovery
- Lateral Movement
- Collection

**📖 [View Complete MITRE ATT&CK Mapping →](./mitre-mapping.md)**

---

### 3. NIST SP 800-115

**Technical Guide to Information Security Testing and Assessment**

This NIST publication guided the technical execution:

**Testing Techniques Applied:**
- Network Discovery
- Vulnerability Scanning
- Penetration Testing
- Security Assessment

**Testing Approaches:**
- Target Identification and Analysis
- Target Vulnerability Validation
- Attack Execution
- Result Analysis and Documentation

🔗 **Reference:** [NIST SP 800-115](https://csrc.nist.gov/publications/detail/sp/800-115/final)

---

### 4. OWASP Testing Guide

For web application components, the **OWASP Testing Guide** informed testing procedures:

**Areas Tested:**
- Information Gathering
- Configuration Management
- Authentication Testing
- Session Management
- Input Validation
- Error Handling

🔗 **Reference:** [OWASP Testing Guide v4](https://owasp.org/www-project-web-security-testing-guide/)

---

## 🔄 Assessment Phases

### Phase 1: Reconnaissance & Planning
**Duration:** 2 hours

**Activities:**
- Reviewed scope and rules of engagement
- Established communication protocols
- Prepared attack platform and tools
- Created evidence collection structure

**Tools Used:**
- Documentation templates
- Network diagrams
- Note-taking systems

---

### Phase 2: Information Gathering
**Duration:** 3 hours

**Activities:**
- Network discovery (ping sweeps, ARP scans)
- Port scanning (full TCP/UDP)
- Service version detection
- DNS enumeration
- SMB enumeration
- LDAP enumeration

**Tools Used:**
- Nmap, Netdiscover, ARP-scan
- enum4linux, smbclient, crackmapexec
- ldapsearch, dnsenum

**Key Findings:**
- 5 active hosts identified
- Flat network topology
- SMB signing not required on 2 systems
- Anonymous LDAP binds allowed

---

### Phase 3: Vulnerability Identification
**Duration:** 4 hours

**Activities:**
- Web application enumeration
- Directory brute-forcing
- Configuration file discovery
- Kerberos user enumeration
- Password policy analysis
- Service vulnerability scanning

**Tools Used:**
- Gobuster, Nikto, WhatWeb
- Kerbrute
- Nmap NSE scripts

**Key Findings:**
- Exposed configuration backup file
- Weak domain password policy (8 chars)
- LLMNR/NBT-NS enabled
- Multiple service accounts with SPNs

---

### Phase 4: Exploitation & Initial Access
**Duration:** 4 hours

**Activities:**
- Configuration file download and analysis
- Database credential extraction
- SSH access with reused credentials
- LLMNR/NBT-NS poisoning
- Password spraying attacks
- AS-REP Roasting
- Hash cracking

**Tools Used:**
- Responder, Hashcat
- CrackMapExec
- Impacket (GetNPUsers)

**Key Achievements:**
- SSH access to Linux server
- Domain user credentials obtained (jthompson)
- Multiple user accounts compromised
- Service account credentials captured

---

### Phase 5: Lateral Movement
**Duration:** 3 hours

**Activities:**
- WinRM access to workstation
- Memory credential dumping
- Pass-the-Hash attacks
- SMB relay attacks (demonstrated)
- File server access
- Share enumeration
- Sensitive data discovery

**Tools Used:**
- Evil-WinRM
- Mimikatz, pypykatz
- CrackMapExec
- Impacket (psexec, smbexec)

**Key Achievements:**
- Workstation compromise (WKSTN-HR-05)
- IT administrator credentials obtained
- File server access (VFS-FS-01)
- Additional credentials discovered in shares

---

### Phase 6: Privilege Escalation
**Duration:** 5 hours

**Activities:**
- BloodHound data collection
- Attack path analysis
- ACL enumeration
- Kerberoasting
- Permission abuse (ForceChangePassword)
- Domain admin account compromise

**Tools Used:**
- BloodHound, SharpHound
- Impacket (GetUserSPNs)
- PowerView
- rpcclient

**Key Achievements:**
- Identified privilege escalation paths
- Service account Kerberoasted
- Domain admin password reset
- Domain admin access achieved

---

### Phase 7: Domain Dominance
**Duration:** 2 hours

**Activities:**
- Domain controller access
- DCSync attack execution
- Credential extraction (all domain users)
- krbtgt hash obtained
- Golden ticket demonstration
- Persistence mechanisms documented

**Tools Used:**
- Impacket (secretsdump, psexec)
- Impacket (ticketer) for golden ticket
- Domain controller enumeration

**Key Achievements:**
- Complete domain compromise
- All domain credentials extracted
- Persistence capability demonstrated
- Full evidence collection

---

### Phase 8: Documentation & Reporting
**Duration:** 8 hours

**Activities:**
- Evidence organization
- Screenshot annotation
- Technical documentation
- Executive summary creation
- Remediation guidance development
- Detection use case creation
- MITRE ATT&CK mapping
- Report review and finalization

**Deliverables:**
- Cover sheet (executive overview)
- Technical assessment report (Part 1)
- Findings & remediation report (Part 2)
- Evidence repository
- MITRE ATT&CK mapping
- Detection use cases

---

## 🛡️ Testing Approach

### White-Box vs. Black-Box

**This Assessment: Gray-Box Approach**

- **Provided Information:**
  - Network range (10.50.0.0/22)
  - Domain name (corp.vanguardfs.local)
  - List of in-scope systems
  
- **Not Provided (Discovered):**
  - User accounts
  - Passwords
  - Service configurations
  - Domain structure
  - ACL permissions

This approach simulates an insider threat or an attacker who has gained initial network access.

---

### Ethical Considerations

**Rules of Engagement Adherence:**
- ✅ Only tested authorized systems within scope
- ✅ Rate-limited password attacks to avoid lockouts
- ✅ Documented all activities with timestamps
- ✅ No destructive actions taken
- ✅ Persistence mechanisms documented but not deployed
- ✅ Immediate reporting of critical findings
- ✅ Proper evidence handling and confidentiality

**Out-of-Scope Activities:**
- ❌ Denial of Service attacks
- ❌ Social engineering
- ❌ Physical security testing
- ❌ Data destruction or modification
- ❌ Attacks on out-of-scope systems

---

## 📊 Risk Assessment Methodology

### CVSS v3.1 Scoring

All vulnerabilities were scored using the Common Vulnerability Scoring System:

**Severity Ratings:**
- **Critical (9.0-10.0):** Immediate action required
- **High (7.0-8.9):** Prompt attention needed
- **Medium (4.0-6.9):** Planned remediation
- **Low (0.1-3.9):** Minor risk
- **Informational (0.0):** Best practice recommendations

**Scoring Factors:**
- Attack Vector (Network, Adjacent, Local)
- Attack Complexity (Low, High)
- Privileges Required (None, Low, High)
- User Interaction (None, Required)
- Confidentiality Impact (None, Low, High)
- Integrity Impact (None, Low, High)
- Availability Impact (None, Low, High)

---

## 🎯 Testing Focus Areas

### Active Directory Security

**Enumeration:**
- User and group enumeration
- Computer object discovery
- Service Principal Name (SPN) identification
- ACL and permission analysis
- Trust relationship mapping

**Authentication Attacks:**
- Password spraying
- AS-REP Roasting
- Kerberoasting
- Pass-the-Hash
- Pass-the-Ticket

**Privilege Escalation:**
- ACL abuse (GenericAll, WriteDacl, ForceChangePassword)
- Group membership exploitation
- Delegation attacks
- GPO abuse vectors

**Persistence:**
- Golden ticket attacks
- Silver ticket attacks
- DCSync rights
- AdminSDHolder abuse

---

### Network Penetration Testing

**Discovery:**
- Host discovery and enumeration
- Service identification
- Version detection
- Vulnerability scanning

**Exploitation:**
- Service exploitation
- Configuration weaknesses
- Default credentials
- Misconfigurations

**Lateral Movement:**
- Network traversal
- Credential reuse
- SMB relay attacks
- Remote service exploitation

---

## 📚 Tools & Technologies

### Primary Toolset

**Reconnaissance:**
- Nmap 7.94
- DNSenum
- Netdiscover

**Active Directory:**
- BloodHound 4.3.1
- Impacket Suite
- CrackMapExec 5.4.0
- Kerbrute
- Responder 3.1.3.0

**Exploitation:**
- Metasploit Framework (minimal use)
- Custom exploit scripts
- Manual exploitation

**Credential Attacks:**
- Hashcat 6.2.6
- John the Ripper
- Mimikatz
- pypykatz

**Post-Exploitation:**
- Evil-WinRM
- PowerView
- PowerShell
- Bash scripts

---

## 🔗 References & Resources

### Standards & Frameworks
- [PTES - Penetration Testing Execution Standard](http://www.pentest-standard.org/)
- [MITRE ATT&CK for Enterprise](https://attack.mitre.org/)
- [NIST SP 800-115](https://csrc.nist.gov/publications/detail/sp/800-115/final)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OSSTMM - Open Source Security Testing Methodology](https://www.isecom.org/OSSTMM.3.pdf)

### Active Directory Security
- [AD Security (adsecurity.org)](https://adsecurity.org/)
- [Harmj0y Blog](http://blog.harmj0y.net/)
- [SpecterOps BloodHound Resources](https://bloodhound.readthedocs.io/)
- [PayloadsAllTheThings - Active Directory](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md)

---

## 📖 Navigation

<div align="center">

[![Back to Project](https://img.shields.io/badge/←-Project_Home-blue?style=for-the-badge)](../README.md)
[![MITRE Mapping](https://img.shields.io/badge/→-MITRE_ATT&CK-red?style=for-the-badge)](./mitre-mapping.md)
[![Technical Report](https://img.shields.io/badge/→-Technical_Assessment-green?style=for-the-badge)](../technical-assessment.md)

</div>

---

*This methodology documentation demonstrates adherence to industry-standard frameworks and professional penetration testing practices.*

**Last Updated:** October 2025
