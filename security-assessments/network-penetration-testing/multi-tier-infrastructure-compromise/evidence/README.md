# Evidence Documentation
## Multi-Tier Infrastructure Compromise Assessment

**Assessment Date:** October 2025  
**Evidence Collection Period:** October 15-19, 2025  
**Classification:** CONFIDENTIAL

---

## ⚠️ Portfolio Presentation Notice

**This evidence directory structure is provided for documentation and portfolio demonstration purposes.**

Due to the sensitive nature of penetration testing evidence and to maintain confidentiality:

- 📁 **Actual evidence files are not included in this public repository**
- 📸 **Screenshots and command outputs are stored securely offline**
- 📋 **This README serves as an index and documentation of evidence collected**
- 🔒 **Original evidence available upon request during interview process**

**What IS included in this repository:**
- Complete technical methodology documentation
- Detailed findings and remediation guidance
- Professional assessment reports
- MITRE ATT&CK framework mapping

**What is NOT included (stored securely offline):**
- Screenshots of exploitation activities
- Raw command output files
- System configuration dumps
- Sensitive evidence artifacts

*If you are reviewing this portfolio for a hiring decision and would like to see actual evidence artifacts, please contact me directly for a private demonstration or secure evidence review.*

---

## Overview

This directory contains evidence artifacts collected during the penetration testing engagement. All evidence has been sanitized to remove client-specific identifying information while maintaining technical accuracy for portfolio demonstration purposes.

---

## Evidence Categories

### 1. Network Reconnaissance
**Files:**
- `01-nmap-gateway-scan.txt` - Initial port scan of gateway.corp.local
- `02-nmap-webapps-scan.txt` - Service enumeration of webapps.corp.local
- `03-smb-share-enumeration.txt` - SMB share discovery output

**Key Findings:**
- Anonymous SMB access identified
- Web services discovered on port 80
- MySQL database exposed on port 3306

---

### 2. Initial Access
**Files:**
- `04-smb-file-retrieval.txt` - Files downloaded from public share
- `05-credentials-discovered.txt` - Retrieved credential file contents
- `06-git-repository-extraction.txt` - Exposed Git repository discovery

**Screenshots:**
- `screenshot-01-smb-anonymous-access.png` - Anonymous SMB connection
- `screenshot-02-credential-file-contents.png` - Exposed credentials
- `screenshot-03-git-directory-exposed.png` - .git directory accessibility

---

### 3. Web Application Exploitation
**Files:**
- `07-web-admin-authentication.txt` - Successful admin panel login
- `08-web-shell-upload.txt` - File upload exploitation
- `09-reverse-shell-connection.txt` - Initial shell establishment

**Screenshots:**
- `screenshot-04-admin-panel-access.png` - Authenticated CMS interface
- `screenshot-05-file-upload-interface.png` - File manager showing upload
- `screenshot-06-web-shell-execution.png` - Shell triggered via HTTP request
- `screenshot-07-reverse-shell-received.png` - Netcat listener receiving connection

---

### 4. Post-Exploitation
**Files:**
- `10-system-enumeration.txt` - OS and kernel information
- `11-network-interface-discovery.txt` - Dual-homed host identification
- `12-database-configuration.txt` - MySQL config file contents
- `13-meterpreter-session.txt` - Meterpreter session establishment

**Screenshots:**
- `screenshot-08-www-data-shell.png` - Initial shell as www-data
- `screenshot-09-meterpreter-sysinfo.png` - Meterpreter system information
- `screenshot-10-dual-network-interfaces.png` - eth0 and eth1 discovery

---

### 5. Credential Harvesting
**Files:**
- `14-mysql-user-enumeration.txt` - Database user table dump
- `15-password-hash-extraction.txt` - Retrieved password hashes
- `16-hashcat-cracking.txt` - Password cracking results

**Screenshots:**
- `screenshot-11-mysql-root-access.png` - Passwordless MySQL connection
- `screenshot-12-user-table-dump.png` - MySQL user credentials
- `screenshot-13-hashcat-success.png` - Successfully cracked password

---

### 6. Lateral Movement
**Files:**
- `17-internal-network-discovery.txt` - Port scan of 172.16.50.0/24
- `18-port-forwarding-config.txt` - Meterpreter port forward setup
- `19-ssh-brute-force.txt` - Hydra attack output

**Screenshots:**
- `screenshot-14-autoroute-configuration.png` - Network pivoting setup
- `screenshot-15-internal-host-discovery.png` - Internal network scan results
- `screenshot-16-ssh-brute-force-success.png` - Successful credential compromise

---

### 7. Privilege Escalation
**Files:**
- `20-sudo-version-identification.txt` - Vulnerable sudo version discovery
- `21-cve-exploit-compilation.txt` - Exploit development process
- `22-privilege-escalation-execution.txt` - Exploit execution
- `23-root-access-verification.txt` - Root shell confirmation

**Screenshots:**
- `screenshot-17-sudo-vulnerability.png` - Sudo version check
- `screenshot-18-exploit-compilation.png` - GCC compilation output
- `screenshot-19-exploit-execution.png` - Running privilege escalation
- `screenshot-20-root-shell-obtained.png` - Root access achieved
- `screenshot-21-root-file-access.png` - Access to /root directory

---

## Evidence Chain of Custody

| Evidence ID | Description | Collection Date | Collection Method |
|-------------|-------------|-----------------|-------------------|
| EVD-001 to EVD-003 | Network reconnaissance | Oct 15, 2025 | Nmap output logs |
| EVD-004 to EVD-006 | Initial access artifacts | Oct 15, 2025 | Command-line capture |
| EVD-007 to EVD-009 | Web exploitation | Oct 16, 2025 | Terminal logs + screenshots |
| EVD-010 to EVD-013 | Post-exploitation | Oct 16, 2025 | Shell command output |
| EVD-014 to EVD-016 | Credential harvesting | Oct 17, 2025 | MySQL client output |
| EVD-017 to EVD-019 | Lateral movement | Oct 17, 2025 | Metasploit logs |
| EVD-020 to EVD-023 | Privilege escalation | Oct 18, 2025 | Shell session logs |

---

## Screenshot Index

### Critical Findings Screenshots

1. **Anonymous SMB Access** (`screenshot-01-smb-anonymous-access.png`)
   - Demonstrates unauthenticated share access
   - Shows credential file retrieval

2. **Exposed Git Repository** (`screenshot-03-git-directory-exposed.png`)
   - Shows .git directory accessible via HTTP
   - Demonstrates source code exposure

3. **Passwordless MySQL Root** (`screenshot-11-mysql-root-access.png`)
   - Shows connection without password
   - Demonstrates database access as root

4. **SSH Brute Force Success** (`screenshot-16-ssh-brute-force-success.png`)
   - Shows Hydra successful authentication
   - Displays cracked credentials

5. **Root Access Achievement** (`screenshot-20-root-shell-obtained.png`)
   - Shows escalation from user to root
   - Demonstrates complete system compromise

---

## Evidence Verification

All evidence has been:
- ✅ Timestamped during collection
- ✅ Sanitized for client confidentiality
- ✅ Cross-referenced with assessment timeline
- ✅ Validated for technical accuracy
- ✅ Organized by exploitation phase

---

## Technical Notes

### File Formats
- **Text Files (.txt):** Command output and terminal logs
- **Screenshots (.png):** Visual evidence of key exploitation steps
- **Logs (.log):** Tool output logs (Metasploit, Hydra, etc.)

### Naming Convention
```
[sequence]-[description]-[target].extension

Examples:
01-nmap-gateway-scan.txt
screenshot-05-file-upload-interface.png
```

### Evidence Integrity
- All text files preserved as-is from terminal output
- Screenshots taken at 1920x1080 resolution
- No post-processing except for sanitization
- Original timestamps preserved in file metadata

---

## Usage Guidelines

### For Portfolio Review
This evidence demonstrates:
- Systematic penetration testing methodology
- Proper documentation practices
- Technical proficiency with security tools
- Professional evidence handling

### For Technical Interviews
Key evidence to highlight:
- Network pivoting configuration (EVD-017, EVD-018)
- Privilege escalation exploit (EVD-020 through EVD-023)
- Multi-stage credential harvesting (EVD-004, EVD-012, EVD-015)
- Complete attack chain progression

---

## Evidence Sanitization

The following information has been modified for confidentiality:
- ✅ IP addresses changed to RFC5737 test ranges
- ✅ Hostnames changed to generic corporate naming
- ✅ Usernames and passwords replaced with realistic examples
- ✅ Organization-specific details removed
- ✅ Personally identifiable information (PII) redacted

**Original Assessment Context Preserved:**
- ✅ Technical accuracy maintained
- ✅ Exploitation timeline accurate
- ✅ Tool output authentic
- ✅ Vulnerability severity unchanged

---

## Contact Information

**Assessment Conducted By:** Vitor Anjos  
**GitHub:** [Offensive Security](https://github.com/Vitor-D-Anjos)  

---

## Disclaimer

*This evidence was collected during a controlled penetration testing engagement in a laboratory environment. All activities were authorized and conducted in accordance with professional penetration testing standards. No unauthorized access to production systems occurred. All identifying information has been sanitized for portfolio presentation purposes.*

---

**Last Updated:** October 2025  
**Evidence Retention:** Maintained for portfolio purposes  
**Classification:** CONFIDENTIAL - Portfolio Use Only
