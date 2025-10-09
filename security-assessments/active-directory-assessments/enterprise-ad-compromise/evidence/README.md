# Evidence Repository

## Structure

evidence/
├── screenshots/
│ ├── initial-access/
│ ├── credential-access/
│ ├── lateral-movement/
│ └── privilege-escalation/
├── command-outputs/
│ ├── nmap-scans/
│ ├── bloodhound-data/
│ └── impacket-outputs/
├── hashes/
│ ├── cracked-passwords.txt
│ └── domain-hashes.txt
└── network-captures/
└── responder-capture.pcap
text


## Evidence Index
- **Screenshot 001:** Exposed config.php.bak file
- **Screenshot 002:** Successful SSH access
- **Screenshot 003:** BloodHound attack paths
- **Screenshot 004:** DCSync successful execution
- **Command Output 001:** Nmap service enumeration
- **Command Output 002:** Kerberoasting results
- **Hash File 001:** Cracked password list

## Verification
All evidence collected during controlled assessment in isolated lab environment.


______________________
_______________________




# 🖼️ Evidence Repository

<div align="center">

[![Back to Project](https://img.shields.io/badge/←_Back_to_Project-Home-blue?style=for-the-badge)](../README.md)
[![View Screenshots](https://img.shields.io/badge/→-Screenshots-green?style=for-the-badge)](./screenshots/)

</div>

---

## 📂 Evidence Organization

This directory contains supporting evidence from the Enterprise Active Directory Compromise assessment. All evidence has been organized by attack phase for easy reference and validation.

---

## 🗂️ Directory Structure

```
evidence/
├── README.md (this file)
│
├── 📁 screenshots/
│   ├── README.md
│   ├── 01-reconnaissance/
│   ├── 02-initial-access/
│   ├── 03-credential-access/
│   ├── 04-lateral-movement/
│   ├── 05-privilege-escalation/
│   └── 06-domain-dominance/
│
├── 📁 logs/
│   ├── nmap_scans/
│   ├── tool_output/
│   └── command_history/
│
└── 📁 data/
    ├── bloodhound_data/
    ├── captured_hashes/
    └── enumeration_results/
```

---

## 📸 Evidence Categories

### 1. Screenshots

**Purpose:** Visual proof of successful exploitation and access

**Organization:** Organized by attack phase
- Reconnaissance findings
- Initial access proof
- Credential capture evidence
- Lateral movement demonstrations
- Privilege escalation proof
- Domain admin access verification

**📖 [View Screenshot Index →](./screenshots/)**

---

### 2. Tool Output Logs

**Purpose:** Raw command output and tool results for validation

**Contents:**
- Nmap scan results (XML and text)
- BloodHound JSON data files
- Impacket command outputs
- CrackMapExec results
- Hashcat cracking sessions
- Responder capture logs

**Format:** Organized by tool and phase

---

### 3. Captured Data

**Purpose:** Artifacts collected during assessment

**Contents:**
- Password hashes (sanitized)
- Enumeration results
- BloodHound graph data
- LDAP dumps
- File listings from shares

**Note:** All sensitive data has been sanitized or removed for portfolio purposes

---

## 📋 Evidence Inventory

### Reconnaissance Phase

| Evidence Type | Description | Location |
|---------------|-------------|----------|
| Nmap Scans | Full port scans of all targets | `logs/nmap_scans/` |
| Network Map | Network topology diagram | `screenshots/01-reconnaissance/` |
| Service Enumeration | Detailed service version info | `logs/tool_output/enum4linux/` |
| DNS Records | Discovered DNS entries | `data/enumeration_results/dns.txt` |
| SMB Enumeration | Share listings and permissions | `data/enumeration_results/smb_shares.txt` |

---

### Initial Access Phase

| Evidence Type | Description | Location |
|---------------|-------------|----------|
| Config File Discovery | Exposed configuration backup | `screenshots/02-initial-access/config_file.png` |
| Database Credentials | Extracted from config.php.bak | `screenshots/02-initial-access/db_creds.png` |
| SSH Access | Shell access to WEB-APP-01 | `screenshots/02-initial-access/ssh_access.png` |
| MySQL Access | Database connection proof | `screenshots/02-initial-access/mysql_access.png` |

---

### Credential Access Phase

| Evidence Type | Description | Location |
|---------------|-------------|----------|
| LLMNR Poisoning | Responder capturing hashes | `screenshots/03-credential-access/responder_capture.png` |
| Captured Hashes | NTLMv2 hashes from poisoning | `data/captured_hashes/llmnr_hashes.txt` |
| Password Cracking | Hashcat successfully cracking | `screenshots/03-credential-access/hashcat_crack.png` |
| Password Spraying | Successful domain user auth | `screenshots/03-credential-access/password_spray.png` |
| ASREPRoasting | backup_admin hash capture | `screenshots/03-credential-access/asreproast.png` |
| Kerberoasting | sql_service ticket extraction | `screenshots/03-credential-access/kerberoast.png` |

---

### Lateral Movement Phase

| Evidence Type | Description | Location |
|---------------|-------------|----------|
| WinRM Access | Evil-WinRM shell on workstation | `screenshots/04-lateral-movement/evil_winrm.png` |
| Mimikatz Execution | Credential dumping from memory | `screenshots/04-lateral-movement/mimikatz.png` |
| Pass-the-Hash | Using NTLM hash for access | `screenshots/04-lateral-movement/pth_attack.png` |
| File Server Access | PSExec to VFS-FS-01 | `screenshots/04-lateral-movement/filesrv_access.png` |
| Share Enumeration | Sensitive data discovery | `screenshots/04-lateral-movement/share_enum.png` |

---

### Privilege Escalation Phase

| Evidence Type | Description | Location |
|---------------|-------------|----------|
| BloodHound Graph | Attack path visualization | `screenshots/05-privilege-escalation/bloodhound_path.png` |
| BloodHound Data | Complete AD enumeration | `data/bloodhound_data/` |
| ACL Abuse | ForceChangePassword exploit | `screenshots/05-privilege-escalation/acl_abuse.png` |
| Password Reset | dadmin password change | `screenshots/05-privilege-escalation/password_reset.png` |
| Domain Admin Proof | Group membership verification | `screenshots/05-privilege-escalation/domain_admin.png` |

---

### Domain Dominance Phase

| Evidence Type | Description | Location |
|---------------|-------------|----------|
| DC Access | Shell on domain controller | `screenshots/06-domain-dominance/dc_shell.png` |
| DCSync Attack | Extracting domain credentials | `screenshots/06-domain-dominance/dcsync.png` |
| Domain Hashes | All user NTLM hashes (sanitized) | `data/captured_hashes/domain_hashes.txt` |
| krbtgt Hash | Golden ticket capability | `screenshots/06-domain-dominance/krbtgt_hash.png` |
| Golden Ticket | Ticket creation demonstration | `screenshots/06-domain-dominance/golden_ticket.png` |

---

## 🔒 Data Sanitization

**Important:** All sensitive data in this evidence repository has been sanitized for portfolio purposes:

### Sanitized Elements:
- ✅ IP addresses changed from original lab
- ✅ Passwords redacted or changed
- ✅ Real usernames replaced with generic names
- ✅ Domain names modified
- ✅ Hash values truncated or modified
- ✅ Customer data removed entirely
- ✅ PII completely redacted

### What Remains:
- ✅ Command syntax and tool usage
- ✅ Attack methodologies
- ✅ Tool outputs (with sanitized values)
- ✅ Screenshots showing techniques (with redactions)
- ✅ Technical procedures and processes

---

## 📊 Evidence Statistics

<table>
  <tr>
    <td align="center"><b>Total Screenshots</b><br/>40+</td>
    <td align="center"><b>Tool Output Files</b><br/>25+</td>
    <td align="center"><b>Data Artifacts</b><br/>15+</td>
  </tr>
  <tr>
    <td align="center"><b>Phases Documented</b><br/>6 phases</td>
    <td align="center"><b>Tools Demonstrated</b><br/>12+ tools</td>
    <td align="center"><b>Techniques Shown</b><br/>15+ ATT&CK</td>
  </tr>
</table>

---

## 🎯 Key Evidence Highlights

### Critical Findings Proof

**1. Exposed Configuration File**
- Screenshot: `screenshots/02-initial-access/config_exposure.png`
- Shows: Browser accessing config.php.bak
- Impact: Database credentials in plaintext

**2. LLMNR Hash Capture**
- Screenshot: `screenshots/03-credential-access/responder_capture.png`
- Shows: Responder capturing NTLMv2 hash
- Impact: First domain user credentials obtained

**3. BloodHound Attack Path**
- Screenshot: `screenshots/05-privilege-escalation/bloodhound_graph.png`
- Shows: Path from jthompson → dadmin (Domain Admin)
- Impact: Clear privilege escalation route identified

**4. DCSync Proof**
- Screenshot: `screenshots/06-domain-dominance/dcsync_output.png`
- Shows: secretsdump extracting all domain hashes
- Impact: Complete domain compromise

---

## 📖 Using This Evidence

### For Technical Review:
1. Browse screenshots by attack phase
2. Review tool output logs for command syntax
3. Examine BloodHound data for attack paths
4. Validate findings with raw data artifacts

### For Presentations:
1. Use screenshots to demonstrate techniques
2. Reference tool outputs for methodology discussions
3. Show BloodHound graphs for visual impact
4. Highlight key findings with annotated images

### For Learning:
1. Study command syntax from logs
2. Understand tool usage patterns
3. Learn from successful exploitation techniques
4. Practice similar methods in your own labs

---

## ⚠️ Important Notes

### Evidence Integrity
- All timestamps preserved where relevant
- Original command syntax maintained
- Tool versions documented
- Chain of custody maintained during assessment

### Portfolio Usage
- All evidence is suitable for portfolio demonstration
- No confidential or sensitive data exposed
- Sanitized per security best practices
- Safe for public GitHub repository

### Ethical Considerations
- All testing performed in authorized lab environment
- No production systems compromised
- No real customer data accessed
- Demonstrates skills ethically and responsibly

---

## 📚 Evidence File Formats

### Screenshots
- **Format:** PNG (lossless compression)
- **Resolution:** 1920x1080 or higher
- **Annotations:** Red boxes for key elements
- **Naming:** Descriptive with phase prefix

### Logs
- **Format:** Text files (.txt, .log)
- **Encoding:** UTF-8
- **Structure:** Timestamped entries
- **Sanitization:** Sensitive values redacted

### Data Files
- **Nmap:** XML and gnmap formats
- **BloodHound:** JSON format
- **Hashes:** Text format (sanitized)
- **Enumeration:** Structured text files

---

## 🔗 Quick Navigation

<div align="center">

[![Project Home](https://img.shields.io/badge/🏠-Project_Home-blue?style=for-the-badge)](../README.md)
[![Screenshots](https://img.shields.io/badge/📸-Screenshots-green?style=for-the-badge)](./screenshots/)
[![Technical Report](https://img.shields.io/badge/📖-Technical_Report-orange?style=for-the-badge)](../technical-assessment.md)
[![Findings](https://img.shields.io/badge/🔍-Findings-red?style=for-the-badge)](../findings-remediation.md)

</div>

---

## 📝 Evidence Checklist

For each finding, the following evidence was collected:

- [x] Screenshot of vulnerability/exploitation
- [x] Tool output showing commands and results
- [x] Timestamp of discovery
- [x] Impact assessment notes
- [x] Remediation verification after fixing
- [x] MITRE ATT&CK technique mapping

---

## 🎓 Learning Resources

Want to practice these techniques yourself?

**Recommended Labs:**
- HackTheBox: Active Directory machines
- TryHackMe: AD Basics and AD Exploitation rooms
- Proving Grounds: AD-focused boxes
- VulnHub: Active Directory VMs

**Books:**
- "Active Directory Security Playbook" - Sean Metcalf
- "Penetration Testing: A Hands-On Introduction to Hacking" - Georgia Weidman

**Online Courses:**
- Offensive Security (OSCP)
- eLearnSecurity (eCPPTv3)
- INE Penetration Testing Professional

---

*This evidence repository demonstrates professional documentation practices and provides comprehensive proof of successful exploitation techniques.*

**Last Updated:** October 2024  
**Classification:** Public Portfolio Demonstration
