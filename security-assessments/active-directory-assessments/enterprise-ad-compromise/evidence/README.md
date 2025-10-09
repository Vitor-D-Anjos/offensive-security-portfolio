# 🖼️ Evidence Repository

<div align="center">

[![Back to Project](https://img.shields.io/badge/←_Back_to_Project-Home-blue?style=for-the-badge)](../README.md)

</div>

---

## 📂 Evidence Documentation

This directory documents the evidence structure and collection methodology used during the Enterprise Active Directory Compromise assessment.

> **Note:** Screenshots and raw evidence files are not included in this public repository due to:
> - Lab environment has been decommissioned
> - Privacy and sanitization considerations
> - Focus on demonstrating methodology and findings documentation
> 
> **All technical findings are fully documented in the [Technical Assessment](../technical-assessment.md) and [Findings Report](../findings-remediation.md) with detailed command outputs and results.**

---

## 📋 Evidence Collection Methodology

During the assessment, evidence was collected following professional standards:

### Collection Standards
- ✅ Screenshots taken at each critical phase
- ✅ Command outputs preserved with timestamps
- ✅ Tool results saved in multiple formats
- ✅ Chain of custody maintained
- ✅ All findings documented in real-time
- ✅ Evidence organized by attack phase

### Evidence Categories Documented

**1. Reconnaissance**
- Network discovery scans (Nmap, ARP-scan)
- Service enumeration results
- DNS and SMB enumeration
- Initial attack surface analysis

**2. Initial Access**
- Exposed configuration file discovery
- Credential extraction from backup files
- Database access verification
- Initial system compromise

**3. Credential Access**
- LLMNR/NBT-NS poisoning captures
- Password spraying results
- Kerberoasting ticket extraction
- AS-REP Roasting hash collection
- Hash cracking success demonstrations

**4. Lateral Movement**
- WinRM session establishment
- Memory credential dumping
- Pass-the-Hash authentication
- File server access
- Sensitive data discovery

**5. Privilege Escalation**
- BloodHound attack path analysis
- ACL permission enumeration
- ForceChangePassword exploitation
- Domain Admin access achievement

**6. Domain Dominance**
- Domain controller access
- DCSync attack execution
- Complete credential extraction
- Persistence mechanism demonstration

---

## 📊 Evidence That Would Be Collected

In a standard engagement, the following evidence types are documented:

### Screenshots (Typical Count: 40-50)
```
evidence/screenshots/
├── 01-reconnaissance/
│   ├── nmap-network-discovery.png
│   ├── service-enumeration.png
│   └── smb-signing-check.png
├── 02-initial-access/
│   ├── config-file-exposure.png
│   ├── database-credentials.png
│   └── ssh-access-obtained.png
├── 03-credential-access/
│   ├── responder-hash-capture.png
│   ├── password-cracking.png
│   ├── kerberoasting-success.png
│   └── password-spray-results.png
├── 04-lateral-movement/
│   ├── evil-winrm-shell.png
│   ├── mimikatz-execution.png
│   └── file-server-access.png
├── 05-privilege-escalation/
│   ├── bloodhound-attack-path.png
│   ├── acl-abuse.png
│   └── domain-admin-proof.png
└── 06-domain-dominance/
    ├── dc-shell-access.png
    ├── dcsync-output.png
    └── domain-hashes-extracted.png
```

### Tool Output Logs
```
evidence/logs/
├── nmap_scans/
│   ├── full_tcp_scan.xml
│   └── service_detection.nmap
├── bloodhound_data/
│   ├── computers.json
│   ├── users.json
│   └── domains.json
├── credential_attacks/
│   ├── responder.log
│   ├── hashcat_session.txt
│   └── crackmapexec_output.txt
└── command_history/
    └── attack_timeline.txt
```

### Data Artifacts (Sanitized)
```
evidence/data/
├── enumeration_results/
│   ├── user_list.txt
│   ├── smb_shares.txt
│   └── dns_records.txt
├── captured_credentials/
│   ├── llmnr_hashes.txt (sanitized)
│   ├── kerberoast_tickets.txt (sanitized)
│   └── domain_hashes.txt (sanitized)
└── bloodhound_analysis/
    └── attack_paths.txt
```

---

## 🎯 Key Findings Evidence Summary

### Critical Finding #1: Exposed Configuration File
**Evidence Type:** Screenshot + File Content  
**What Would Be Shown:**
- Browser accessing `http://10.50.1.45/config.php.bak`
- Plaintext database credentials visible
- Successful SSH authentication using reused credentials

**Impact:** Initial access to Linux server, database access, 2,847 customer records exposed

---

### Critical Finding #2: LLMNR Poisoning Success
**Evidence Type:** Tool Output + Hash Capture  
**What Would Be Shown:**
- Responder running and capturing authentication
- NTLMv2 hash for user `jthompson` captured
- Hashcat successfully cracking the hash to `Summer2024!`

**Impact:** First domain user credentials obtained within 12 minutes

---

### Critical Finding #3: Kerberoasting Attack
**Evidence Type:** Ticket Extraction + Cracking  
**What Would Be Shown:**
- GetUserSPNs extracting service ticket for `sql_service`
- Hashcat cracking session
- Password cracked in 4 minutes 37 seconds: `SQLSvc#2024!Backup`

**Impact:** Service account with elevated permissions compromised

---

### Critical Finding #4: BloodHound Attack Path
**Evidence Type:** Graph Visualization  
**What Would Be Shown:**
- BloodHound graph showing path: mrodriguez → ForceChangePassword → dadmin
- ACL permission details
- Shortest path to Domain Admins (1 hop)

**Impact:** Clear privilege escalation route identified and exploited

---

### Critical Finding #5: DCSync Attack
**Evidence Type:** Command Output  
**What Would Be Shown:**
- secretsdump command execution
- All domain NTLM hashes extracted
- krbtgt hash obtained (golden ticket capability)
- Complete domain compromise proven

**Impact:** Full domain control achieved

---

## 📝 Alternative Evidence in Technical Report

Since screenshots are not available, all evidence is comprehensively documented in the technical reports through:

### 1. Detailed Command Outputs
Every command executed is documented with:
```bash
# Command used
nmap -sV -sC -p- 10.50.1.45

# Results obtained
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu
80/tcp   open  http    Apache httpd 2.4.41
3306/tcp open  mysql   MySQL 8.0.26
```

### 2. Tool Result Descriptions
Detailed descriptions of tool outputs:
- What was discovered
- How it was exploited
- What access was gained
- Impact assessment

### 3. Attack Chain Documentation
Step-by-step progression:
- Initial enumeration findings
- Exploitation methods
- Access gained at each step
- Credentials obtained
- Systems compromised

### 4. MITRE ATT&CK Mapping
Each technique documented with:
- Tactic and technique ID
- Tools used
- Commands executed
- Detection opportunities
- Defensive recommendations

---

## 🔍 Verification of Findings

### How Findings Can Be Validated

**1. Reproducible Commands**
All commands are documented in the technical report with exact syntax, allowing reproduction in similar environments.

**2. Methodology Documentation**
Complete methodology section shows:
- Standard penetration testing frameworks followed (PTES, NIST)
- Industry-standard tools used
- Professional approach demonstrated

**3. Detailed Technical Analysis**
Each finding includes:
- CVSS scoring and justification
- Business impact analysis
- Remediation guidance
- Detection recommendations

**4. MITRE ATT&CK Mapping**
All techniques mapped to recognized adversary behaviors, demonstrating real-world relevance.

---

## 💼 Professional Documentation Approach

### This Portfolio Demonstrates:

✅ **Understanding of Evidence Collection**
- Knowledge of what evidence to collect
- How to organize evidence professionally
- Proper documentation standards

✅ **Professional Reporting Skills**
- Comprehensive technical documentation
- Clear communication of findings
- Actionable remediation guidance

✅ **Technical Competency**
- Detailed command-line examples
- Tool proficiency across multiple platforms
- Understanding of attack chains

✅ **Business Communication**
- Risk assessment and prioritization
- Financial impact analysis
- Executive-level summaries

---

## 🎓 Creating Your Own Evidence

### Want to Add Screenshots Later?

If you recreate this assessment in your own lab:

**1. Set Up Similar Environment**
- Build Windows AD domain
- Deploy vulnerable configurations
- Document baseline

**2. Perform Assessment**
- Follow methodology from technical report
- Take screenshots at each phase
- Capture tool outputs

**3. Organize Evidence**
- Use the directory structure documented here
- Follow naming conventions
- Sanitize appropriately

**4. Update Repository**
- Add screenshots to appropriate directories
- Update evidence README
- Link from technical reports

---

## 🔗 Related Documentation

<div align="center">

[![Technical Report](https://img.shields.io/badge/📖-Technical_Assessment-green?style=for-the-badge)](../technical-assessment.md)
[![Findings](https://img.shields.io/badge/🔍-Findings_&_Remediation-red?style=for-the-badge)](../findings-remediation.md)
[![Methodology](https://img.shields.io/badge/📋-Methodology-purple?style=for-the-badge)](../methodology/)
[![Project Home](https://img.shields.io/badge/🏠-Project_Home-blue?style=for-the-badge)](../README.md)

</div>

---

## 📚 Evidence Best Practices

### For Future Assessments

**During Assessment:**
- Take screenshots in real-time
- Document commands immediately
- Save all tool outputs
- Timestamp everything
- Organize by phase as you go

**Post-Assessment:**
- Review all evidence for completeness
- Sanitize sensitive information
- Organize in clear directory structure
- Cross-reference with report findings
- Store securely with encryption

**For Portfolio:**
- Ensure complete sanitization
- Remove any real organizational data
- Verify no production system info
- Get appropriate approvals if needed
- Consider using lab recreations

---

## ⚖️ Professional Standards

This evidence collection methodology follows:

- **NIST SP 800-86:** Guide to Integrating Forensic Techniques into Incident Response
- **ISO/IEC 27037:** Guidelines for identification, collection, acquisition, and preservation of digital evidence
- **PTES:** Penetration Testing Execution Standard documentation guidelines
- **Industry Best Practices:** Professional penetration testing documentation standards

---

*While screenshots are not included in this public repository, the comprehensive technical documentation in this portfolio demonstrates professional penetration testing methodology, findings documentation, and reporting capabilities.*

**Last Updated:** October 2024  
**Documentation Status:** Complete (Evidence structure documented, screenshots not included)
