# Internal Network Penetration Test
## Active Directory Security Assessment

<div align="center">

[![Back to Portfolio](https://img.shields.io/badge/←_Back_to_Portfolio-Main_Page-blue?style=for-the-badge)](../../../README.md)
[![View Technical Assessment](https://img.shields.io/badge/Read-Technical_Report-green?style=for-the-badge)](./technical-assessment.md)
[![View Findings](https://img.shields.io/badge/Read-Findings_&_Remediation-red?style=for-the-badge)](./findings-remediation.md)

</div>

---

### 📋 PROJECT OVERVIEW

This penetration testing engagement represents a comprehensive security assessment of a simulated enterprise Active Directory environment. The project demonstrates advanced offensive security techniques, methodical attack chain execution, and professional security reporting capabilities developed through hands-on training and certification.

**Assessment Type:** Internal Network Penetration Test  
**Target Environment:** Simulated Financial Services Organization  
**Duration:** 48-hour assessment window  
**Methodology:** PTES, MITRE ATT&CK, NIST SP 800-115  
**Date Completed:** September 2025

---

### 🔬 LAB ENVIRONMENT SETUP

**Network Architecture:**
- **Network Scope:** 10.50.0.0/22 (sanitized from original lab)
- **Domain:** corp.vanguardfs.local
- **Attack Platform:** Kali Linux 2024.2 (10.50.1.150)

**Target Infrastructure:**

| System | Role | IP Address | OS |
|--------|------|------------|-----|
| WEB-APP-01 | Web/Application Server | 10.50.1.45 | Ubuntu 20.04 LTS |
| WKSTN-HR-05 | Employee Workstation | 10.50.1.78 | Windows 10 Enterprise |
| VFS-DC-01 | Secondary Domain Controller | 10.50.2.10 | Windows Server 2019 |
| VFS-DC-02 | Primary Domain Controller | 10.50.2.11 | Windows Server 2019 |
| VFS-FS-01 | File Server | 10.50.3.50 | Windows Server 2019 |

**Lab Purpose:**  
This controlled environment was purpose-built to simulate a realistic enterprise Active Directory deployment with intentional security misconfigurations commonly found in production environments. All testing was conducted in an isolated, authorized laboratory setting.

---

### 🎯 KEY FINDINGS & ACHIEVEMENTS

**Assessment Outcome:** ✅ Complete Domain Compromise Achieved

**Critical Vulnerabilities Identified:** 4  
**High-Risk Issues:** 4  
**Time to Domain Admin:** 16 hours  
**Systems Compromised:** 5/5 (100%)

**Primary Attack Chain:**
```
Config File Exposure → SSH Access → LLMNR Poisoning → 
Domain User Credentials → Kerberoasting → ACL Abuse → 
Domain Admin → DCSync → Complete Domain Control
```

**Most Impactful Findings:**
1. 🔴 **Exposed Configuration File** - Database credentials in plaintext (CVSS 9.8)
2. 🔴 **Weak Password Policy** - Enabled credential spraying attacks (CVSS 9.1)
3. 🔴 **SMB Signing Disabled** - Allowed NTLM relay attacks (CVSS 8.1)
4. 🔴 **Service Account Weakness** - Kerberoastable with excessive permissions (CVSS 8.8)

---

### 💡 KEY TAKEAWAYS & SKILLS DEMONSTRATED

**Technical Competencies:**
- ✅ Active Directory enumeration and exploitation
- ✅ Kerberos-based attacks (Kerberoasting, ASREPRoasting)
- ✅ Credential harvesting techniques (LLMNR poisoning, password spraying)
- ✅ Lateral movement via Pass-the-Hash and WinRM
- ✅ BloodHound analysis for privilege escalation paths
- ✅ DCSync attacks and domain persistence techniques
- ✅ Linux and Windows post-exploitation
- ✅ Network reconnaissance and service enumeration

**MITRE ATT&CK Techniques Applied:**
- T1190 (Exploit Public-Facing Application)
- T1110.003 (Password Spraying)
- T1557.001 (LLMNR/NBT-NS Poisoning)
- T1558.003 (Kerberoasting)
- T1003.006 (DCSync)
- T1021.006 (WinRM Lateral Movement)
- T1550.002 (Pass-the-Hash)

**Professional Skills:**
- 📊 Comprehensive penetration test reporting
- 💼 Business impact analysis and risk assessment
- 🔍 Detection engineering and monitoring recommendations
- 🛡️ Actionable remediation strategies with cost estimates
- 📈 Compliance mapping (PCI-DSS, NIST CSF)
- 🎓 Clear communication for technical and executive audiences

**🔗 [View Complete MITRE ATT&CK Mapping →](./methodology/mitre-mapping.md)**

---

### 📈 BUSINESS IMPACT ASSESSMENT

**Estimated Financial Impact of Real Breach:** $3.5M - $10M
- Incident response and forensics: $500K - $1.5M
- Regulatory fines (PCI-DSS, GDPR): $1M - $5M
- Customer notification and credit monitoring: $500K - $1M
- Legal fees and settlements: $1M - $2M
- Reputational damage: Ongoing

**Data at Risk:**
- 15,000+ customer financial records
- Employee PII (1,247 records)
- Proprietary business documents
- Authentication credentials for all domain users

---

### 🛠️ TOOLS & TECHNOLOGIES UTILIZED

**Reconnaissance:** Nmap, DNSenum, Kerbrute  
**Exploitation:** Impacket Suite, Responder, CrackMapExec  
**Credential Access:** Hashcat, Mimikatz, pypykatz  
**Analysis:** BloodHound, PowerView, ldapsearch  
**Post-Exploitation:** Evil-WinRM, PSExec, PowerShell

**🔗 [View Detailed Methodology →](./methodology/)**

---

### 📚 REMEDIATION HIGHLIGHTS

**Immediate Actions (Week 1):**
- Force password resets for compromised accounts
- Enable SMB signing domain-wide via Group Policy
- Remove exposed configuration files
- Disable LLMNR and NetBIOS-NS

**Strategic Improvements (Year 1):**
- Deploy Microsoft LAPS for local admin password management
- Implement MFA for all privileged accounts
- Migrate service accounts to Group Managed Service Accounts (gMSA)
- Deploy EDR solution on all endpoints
- Implement SIEM with detection use cases
- Network segmentation via VLANs

**Estimated Remediation Budget:** $350,000 - $900,000 (Year 1)  
**ROI:** 5-10x return vs. average breach cost of $4.45M

**📖 [Read Complete Remediation Strategy →](./findings-remediation.md#5-remediation-strategy)**

---

### 🎓 CERTIFICATIONS & TRAINING

This project demonstrates expertise gained through:
- **eCPPTv3** - Certified Professional Penetration Tester
- **INE** - Penetration Testing Professional SkillCheck (100%)
- **INE** - Advanced Penetration Testing
- Hands-on Active Directory security training

**🔗 [View All Certifications →](../../../certifications/)**

---

### 📧 CONTACT INFORMATION

**Penetration Tester:** Vitor Anjos     
**GitHub:** [GitHub](https://github.com/Vitor-D-Anjos)  
**Portfolio:** [Offensive Security](https://github.com/Vitor-D-Anjos/offensive-security-portfolio)

**🔗 [Learn More About My Background →](../../../about-me.md)**

---

### ⚖️ LEGAL DISCLAIMER

**Important:** This penetration test was conducted in a controlled, isolated laboratory environment specifically created for security training and professional development. All systems, networks, and data were owned/controlled by the tester. No unauthorized access to production systems or third-party infrastructure occurred. This assessment demonstrates professional penetration testing capabilities for portfolio and career development purposes only.

**Environment:** Simulated Enterprise Lab  
**Authorization:** Self-authorized training environment  
**Classification:** Public Portfolio Demonstration  
**Standards Compliance:** Adheres to ethical hacking guidelines and industry best practices

---

### 📄 REPORT STRUCTURE

This assessment includes:

| Document | Description | Link |
|----------|-------------|------|
| **Cover Sheet** | Executive overview and quick reference | *You are here* |
| **Part 1: Technical Assessment** | Detailed exploitation walkthrough (Phases 1-5) | [Read Technical Report →](./technical-assessment.md) |
| **Part 2: Findings & Remediation** | Vulnerabilities, remediation, detection strategies | [Read Findings →](./findings-remediation.md) |
| **Methodology** | PTES, MITRE ATT&CK mapping, frameworks | [View Methodology →](./methodology/) |
| **Evidence** | Screenshots and proof of compromise | [View Evidence →](./evidence/) |

**Total Pages:** ~50 pages of comprehensive documentation  
**Evidence Files:** Screenshots, logs, and command outputs organized by attack phase

---

### 🗺️ NAVIGATION

<div align="center">

**Quick Links:**

[![Main Portfolio](https://img.shields.io/badge/🏠-Main_Portfolio-blue?style=for-the-badge)](../../../README.md)
[![About Me](https://img.shields.io/badge/👤-About_Me-green?style=for-the-badge)](../../../about-me.md)
[![Technical Report](https://img.shields.io/badge/📖-Technical_Assessment-orange?style=for-the-badge)](./technical-assessment.md)
[![Findings](https://img.shields.io/badge/🔍-Findings_&_Remediation-red?style=for-the-badge)](./findings-remediation.md)
[![Methodology](https://img.shields.io/badge/📋-Methodology-purple?style=for-the-badge)](./methodology/)
[![Evidence](https://img.shields.io/badge/🖼️-Evidence-yellow?style=for-the-badge)](./evidence/)

</div>

---

### 📊 PROJECT STATISTICS

<table>
  <tr>
    <td align="center"><b>Assessment Duration</b><br/>48 hours</td>
    <td align="center"><b>Time to Domain Admin</b><br/>16 hours</td>
    <td align="center"><b>Systems Compromised</b><br/>5/5 (100%)</td>
  </tr>
  <tr>
    <td align="center"><b>Critical Findings</b><br/>4 vulnerabilities</td>
    <td align="center"><b>High Findings</b><br/>4 vulnerabilities</td>
    <td align="center"><b>MITRE Techniques</b><br/>10+ demonstrated</td>
  </tr>
  <tr>
    <td align="center"><b>Business Impact</b><br/>$3.5M - $10M</td>
    <td align="center"><b>Report Pages</b><br/>50+ pages</td>
    <td align="center"><b>Evidence Items</b><br/>Multiple artifacts</td>
  </tr>
</table>

---

### 🔥 HIGHLIGHT REEL

**What Makes This Assessment Stand Out:**

✨ **Complete Kill Chain** - From reconnaissance to domain dominance  
✨ **Real-World Techniques** - Industry-standard tools and methodologies  
✨ **Comprehensive Documentation** - Professional reporting with evidence  
✨ **Business Focus** - Risk quantification and financial impact analysis  
✨ **Detection Engineering** - SIEM use cases and monitoring recommendations  
✨ **Remediation Guidance** - Actionable fixes with timelines and costs  
✨ **MITRE ATT&CK Mapping** - Complete TTP documentation  
✨ **Compliance Alignment** - PCI-DSS and NIST CSF mapping  

---

### 📖 READING GUIDE

**For Technical Audiences:**
1. Start with [Technical Assessment](./technical-assessment.md) for exploitation details
2. Review [Methodology](./methodology/) for framework alignment
3. Check [Evidence](./evidence/) for proof screenshots

**For Management/Executive:**
1. Read this cover sheet for overview
2. Review business impact section above
3. Jump to [Findings & Remediation](./findings-remediation.md#3-findings--vulnerabilities) for risk summary
4. Focus on [Remediation Strategy](./findings-remediation.md#5-remediation-strategy) for action items

**For Security Teams:**
1. Review complete [Findings](./findings-remediation.md#3-findings--vulnerabilities)
2. Study [Detection & Monitoring](./findings-remediation.md#6-detection--monitoring-recommendations)
3. Reference [MITRE ATT&CK Mapping](./methodology/mitre-mapping.md)
4. Implement [Remediation Actions](./findings-remediation.md#5-remediation-strategy)

---

### 🌟 KEY ACHIEVEMENTS

This project successfully demonstrates:

✅ **Advanced Active Directory Exploitation**
- Kerberoasting and AS-REP Roasting attacks
- BloodHound-based privilege escalation path identification
- ACL abuse for domain compromise
- DCSync credential extraction

✅ **Comprehensive Attack Chain Execution**
- Initial access through configuration exposure
- Credential harvesting via LLMNR poisoning
- Lateral movement using Pass-the-Hash
- Domain dominance with Domain Admin access

✅ **Professional Security Reporting**
- Executive summary for business stakeholders
- Detailed technical documentation with evidence
- CVSS-scored vulnerability findings
- Prioritized remediation roadmap with costs

✅ **Detection & Blue Team Support**
- SIEM correlation rules and use cases
- Event log monitoring recommendations
- Attack detection opportunities identified
- Threat hunting guidance provided

---

**For detailed technical findings, remediation guidance, and detection strategies, please refer to the complete assessment report.**

---

<div align="center">

### 📚 Additional Resources

[![AD Assessments Overview](https://img.shields.io/badge/📁-All_AD_Assessments-blue?style=for-the-badge)](https://github.com/Vitor-D-Anjos/offensive-security-portfolio/tree/main/security-assessments/active-directory-assessments/enterprise-ad-compromise)
[![Certifications](https://img.shields.io/badge/🎓-Certifications-green?style=for-the-badge)](../../../certifications/)
[![Back to Main Portfolio](https://img.shields.io/badge/🏠-Main_Portfolio-orange?style=for-the-badge)](../../../README.md)

---

*This cover sheet provides a high-level overview of the penetration testing engagement. All information has been sanitized and modified from the original lab environment to protect infrastructure details while demonstrating professional security assessment capabilities.*

**Document Version:** 1.0  
**Last Updated:** October 2025  
**Report ID:** VFS-PENTEST-2025-09  
**Classification:** Public Portfolio Demonstration

---

**Built with 🔐 by Vitor Anjos**

*"The only truly secure system is one that is powered off, cast in a block of concrete and sealed in a lead-lined room with armed guards." - Gene Spafford*

