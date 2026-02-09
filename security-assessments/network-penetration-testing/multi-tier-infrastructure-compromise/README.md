# Multi-Tier Infrastructure Compromise

## Assessment Overview

**Assessment Type:** Black-Box Network Penetration Test  
**Environment:** Multi-tier corporate infrastructure  
**Scope:** 3 hosts across 2 network segments  
**Methodology:** PTES (Penetration Testing Execution Standard)  
**Duration:** 5-day engagement  
**Classification:** CONFIDENTIAL

---

## Executive Summary

This assessment successfully demonstrated a complete attack chain from external reconnaissance to full administrative compromise across a segmented network infrastructure. Critical vulnerabilities in access controls, authentication mechanisms, and system configurations enabled unauthorized access and privilege escalation across all target systems.

**Key Findings:**
- 6 Critical vulnerabilities identified
- 3 systems fully compromised
- Complete administrative access achieved
- Multi-network lateral movement demonstrated

---

## Attack Chain Overview

```
[External Access]
      ↓
[SMB Anonymous Access] → Credential Discovery
      ↓
[Web Application Compromise] → Initial Foothold
      ↓
[Database Credential Harvest] → Privilege Information
      ↓
[Network Pivoting] → Internal Network Access
      ↓
[SSH Brute Force] → User-Level Access
      ↓
[Privilege Escalation CVE] → Root Access
```

---

## Target Infrastructure

### External Network (10.50.100.0/24)
- **gateway.corp.local** (10.50.100.10) - Primary gateway with SMB services
- **webapps.corp.local** (10.50.100.20) - Web application server

### Internal Network (172.16.50.0/24)
- **vault.corp.internal** (172.16.50.15) - Internal secure host

---

## Assessment Breakdown

### Phase 1: Reconnaissance & Discovery
**Duration:** 3 hours  
**Activities:**
- Network mapping and service enumeration
- SMB share discovery and analysis
- Web application fingerprinting
- Git repository extraction

**Key Findings:**
- Anonymous SMB access enabled
- Exposed .git directory on web server
- Weak authentication mechanisms

### Phase 2: Initial Access & Exploitation
**Duration:** 7 hours  
**Activities:**
- Credential harvesting from SMB shares
- Web application authentication bypass
- File upload exploitation
- Reverse shell establishment

**Key Achievement:** Obtained foothold on webapps.corp.local as www-data user

### Phase 3: Post-Exploitation & Lateral Movement
**Duration:** 24 hours  
**Activities:**
- Database credential extraction (MySQL root)
- Password hash cracking
- Multi-network discovery and mapping
- Meterpreter session establishment
- Network pivoting configuration

**Key Achievement:** Discovered and accessed internal 172.16.50.0/24 network

### Phase 4: Privilege Escalation
**Duration:** 15 hours  
**Activities:**
- SSH brute force attack on internal host
- Vulnerability research and identification
- CVE-2025-32463 exploitation
- Root access verification

**Key Achievement:** Full administrative access to vault.corp.internal

### Phase 5: Documentation & Reporting
**Duration:** 9 hours  
**Activities:**
- Evidence compilation and organization
- Technical report writing
- Remediation recommendation development
- MITRE ATT&CK mapping

---

## Critical Vulnerabilities Discovered

| ID | Vulnerability | Severity | CVSS | Host |
|----|--------------|----------|------|------|
| VULN-001 | Anonymous SMB Access | Critical | 9.8 | gateway.corp.local |
| VULN-002 | Exposed Git Repository | High | 8.6 | webapps.corp.local |
| VULN-003 | Passwordless MySQL Root | Critical | 9.9 | webapps.corp.local |
| VULN-004 | Weak SSH Authentication | High | 8.8 | vault.corp.internal |
| VULN-005 | CVE-2025-32463 (sudo) | Critical | 9.3 | vault.corp.internal |
| VULN-006 | Inadequate Network Segmentation | High | 8.1 | All systems |

---

## Tools & Techniques

### Reconnaissance
- **Nmap** - Network mapping and service enumeration
- **SMBClient** - SMB share enumeration

### Exploitation
- **Metasploit Framework** - Payload generation and session management
- **Custom PHP Web Shell** - Initial access vector
- **Hydra** - SSH authentication attacks

### Post-Exploitation
- **MySQL Client** - Database enumeration
- **Hashcat** - Password hash cracking
- **Meterpreter** - Advanced post-exploitation and pivoting

### Privilege Escalation
- **GCC** - Custom exploit compilation
- **CVE-2025-32463 Exploit** - sudo privilege escalation

---

## Skills Demonstrated

### Technical Competencies
- ✅ Network reconnaissance and enumeration
- ✅ Service vulnerability identification
- ✅ Web application exploitation
- ✅ Database security assessment
- ✅ Password hash cracking
- ✅ Multi-network pivoting and lateral movement
- ✅ SSH security testing
- ✅ Linux privilege escalation
- ✅ CVE research and exploitation
- ✅ Meterpreter advanced usage

### Professional Skills
- ✅ Methodical assessment approach
- ✅ Evidence collection and documentation
- ✅ Risk assessment and prioritization
- ✅ Clear technical communication
- ✅ Remediation-focused recommendations
- ✅ MITRE ATT&CK framework mapping

---

## Assessment Timeline

```
Day 1 (8 hours)
├── Initial reconnaissance
├── Port scanning and service enumeration
├── SMB share discovery
└── Credential extraction

Day 2 (10 hours)
├── Web application analysis
├── Git repository extraction
├── Initial access establishment
└── Reverse shell deployment

Day 3 (12 hours)
├── Database enumeration
├── Credential harvesting
├── Hash cracking
├── Meterpreter session establishment
└── Internal network discovery

Day 4 (10 hours)
├── Network pivoting configuration
├── Internal host enumeration
├── SSH brute force attack
└── User-level access achieved

Day 5 (10 hours)
├── Privilege escalation research
├── CVE-2025-32463 exploitation
├── Root access verification
└── Initial documentation

Documentation Phase (9 hours)
├── Evidence organization
├── Technical report writing
├── Remediation recommendations
└── Executive summary preparation
```

**Total Assessment Time:** ~50 hours

*Note: This timeframe reflects comprehensive manual testing methodology and professional documentation practices expected in real-world penetration testing engagements.*

---

## Impact Assessment

### Business Impact
- **Confidentiality:** HIGH - Full access to sensitive data across all systems
- **Integrity:** HIGH - Ability to modify critical system configurations
- **Availability:** HIGH - Potential for denial of service across infrastructure

### Technical Impact
- Complete compromise of external gateway
- Full database access with ability to extract/modify data
- Administrative access to internal secure vault system
- Ability to persist and maintain access indefinitely

---

## Document Structure

This assessment is documented across multiple files:

1. **[README.md](./README.md)** - This overview document
2. **[executive-summary.md](./executive-summary.md)** - High-level business summary
3. **[technical-report.md](./technical-report.md)** - Detailed technical walkthrough
4. **[findings-remediation.md](./findings-remediation.md)** - Vulnerability details and fixes
5. **[methodology/mitre-attack-mapping.md](./methodology/mitre-attack-mapping.md)** - ATT&CK framework mapping

---

## Key Takeaways

### For Security Teams
This assessment demonstrates how layered vulnerabilities compound to enable complete infrastructure compromise. No single vulnerability was catastrophic, but their combination created a critical security risk.

### For Hiring Managers
This project showcases:
- Systematic penetration testing methodology
- Advanced post-exploitation techniques
- Real-world network pivoting skills
- Current CVE exploitation knowledge
- Professional documentation capabilities
- Business-focused security communication

---

## Remediation Status

All vulnerabilities have been documented with detailed remediation steps prioritized by risk level:
- **Priority 1 (Immediate):** 4 critical findings requiring immediate action
- **Priority 2 (Short-term):** 3 high-severity items for 30-day remediation
- **Priority 3 (Long-term):** 5 medium-severity items for ongoing improvement

See [findings-remediation.md](./findings-remediation.md) for complete remediation guidance.

---

## Contact Information

**Assessment Conducted By:** Vitor Anjos  
**Date:** October 2025  
**Portfolio:** [Offensive Security](https://github.com/Vitor-D-Anjos)  

---

*This assessment was conducted in a controlled lab environment for educational and portfolio demonstration purposes. All identifying information has been sanitized to protect proprietary details.*
