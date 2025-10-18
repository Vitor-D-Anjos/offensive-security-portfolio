# Multi-Tier Network Penetration Test

## Quick Overview
- **Objective**: Full network compromise assessment
- **Duration**: Simulated 4-hour engagement  
- **Result**: Complete domain administrative access achieved
- **Key Findings**: 6 critical vulnerabilities chained for full compromise

## Attack Path
1. **Initial Access**: Anonymous SMB → Credential theft
2. **Web Compromise**: Stolen credentials → Reverse shell
3. **Lateral Movement**: Database access → Internal network pivoting
4. **Privilege Escalation**: CVE-2025-32463 → Root access

## Skills Demonstrated
- Network reconnaissance & service enumeration
- SMB exploitation & credential harvesting
- Web application testing & shell deployment
- Database security assessment
- Lateral movement & network pivoting
- Privilege escalation & CVE exploitation

## Quick Links
- [Technical Report](technical-report.md)
- [Findings & Remediation](findings-remediation.md)
- [Methodology](methodology/README.md)
- [Evidence](evidence/README.md)
