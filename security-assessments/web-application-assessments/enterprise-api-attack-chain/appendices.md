# Appendices

## Appendix A: Assessment Methodology

### A.1 Testing Framework

This penetration test was conducted following industry-standard methodologies:

- **OWASP Testing Guide v4** - Web application testing methodology
- **OWASP API Security Top 10 (2023)** - API-specific vulnerability assessment
- **PTES (Penetration Testing Execution Standard)** - Overall engagement framework
- **NIST SP 800-115** - Technical guide to information security testing

### A.2 Assessment Phases

| Phase | Duration | Activities |
|-------|----------|------------|
| **1. Reconnaissance** | 2 hours | Network scanning, service enumeration, technology fingerprinting, endpoint discovery |
| **2. Vulnerability Identification** | 3 hours | Manual testing, automated scanning, source code analysis, API schema review |
| **3. Exploitation** | 3 hours | Proof-of-concept development, attack chaining, privilege escalation |
| **4. Post-Exploitation** | 1 hour | Internal service access, data extraction, persistence analysis |
| **5. Documentation** | 1 hour | Finding documentation, evidence collection, report writing |

### A.3 Testing Limitations

1. **Time Constraints:** The assessment was conducted over a 10-hour continuous period, limiting the depth of enumeration possible for some components.

2. **Scope Restrictions:** Direct infrastructure attacks (SSH brute-force, OS exploitation) were excluded per the rules of engagement.

3. **Environment Specificity:** Findings were validated in a single production-like environment. Variations may exist across different deployment contexts.

4. **No Source Code Access:** The assessment was conducted in a black-box configuration without access to backend source code.

### A.4 Risk Rating Methodology

Severity ratings follow the Common Vulnerability Scoring System (CVSS) v3.1:

| Severity | CVSS Score | Description |
|----------|------------|-------------|
| **Critical** | 9.0 - 10.0 | Immediate threat to core business, easily exploitable |
| **High** | 7.0 - 8.9 | Significant security impact, moderate exploitation difficulty |
| **Medium** | 4.0 - 6.9 | Notable security weakness requiring attention |
| **Low** | 0.1 - 3.9 | Minor security issue |
| **Informational** | N/A | Observation for security hardening |

---

### A.5 CVSS Rationale — Finding V-05 (JWT Algorithm Confusion)

The following documents the metric-by-metric rationale for the highest-scoring finding in this assessment.

**Vector String:** AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H — **Score: 9.8 (Critical)**

| Metric | Value | Rationale |
|--------|-------|-----------|
| **Attack Vector (AV)** | Network (N) | The JWKS endpoint is publicly accessible over HTTP. No physical or local access required. |
| **Attack Complexity (AC)** | Low (L) | The technique is well-documented (CVE-2016-10555 pattern), publicly available tooling exists (jwt_tool, jwt-cracker), and the exploit requires approximately 20 lines of Python once the public key is obtained. The attacker need only retrieve a public key from a known endpoint and execute a script. No race conditions, user interaction, or unusual conditions are required. |
| **Privileges Required (PR)** | None (N) | The JWKS endpoint serves public keys without authentication. The forged token is presented directly to the vault endpoint. No prior authentication is needed. |
| **User Interaction (UI)** | None (N) | The attack is fully automated. No user clicks a link, fills a form, or performs any action. |
| **Scope (S)** | Changed (C) | The forged token grants access to the internal vault service, which is a separate security boundary from the authentication service where the vulnerability exists. |
| **Confidentiality Impact (C)** | High (H) | All vault secrets are exposed: database credentials, cloud provider root keys, and internal API signing keys. |
| **Integrity Impact (I)** | High (H) | The forged token allows creation of arbitrary users and modification of existing accounts across the system. |
| **Availability Impact (A)** | High (H) | Possession of cloud root keys and database credentials enables deletion or destruction of critical infrastructure. |

**Note on AC:L:** Although the technique requires knowledge of JWT structure and cryptographic concepts, CVSS defines Attack Complexity as "conditions beyond the attacker's control" rather than attacker skill level. No conditions beyond the attacker's control are required: the public key is available without authentication, the algorithm header is trusted by the server, and the exploitation technique is documented and tooled.

---

## Appendix B: Tools Used

| Tool | Version | Purpose |
|------|---------|---------|
| **nmap** | 7.94 | Network scanning and service detection |
| **curl** | 8.8.0 | HTTP client for manual request testing |
| **jq** | 1.7 | JSON parsing and analysis |
| **Python 3** | 3.11+ | Scripting and cryptographic operations |
| **OpenSSL** | 3.x | HMAC computation and certificate analysis |
| **base64** | GNU coreutils | Base64 encoding/decoding for JWT manipulation |
| **bash** | 5.x | Shell scripting for automation |
| **Git** | 2.x | Version control for documentation |

### Custom Scripts

| Script | Purpose |
|--------|---------|
| `recon.sh` | Automated endpoint and file discovery |
| `jwt_decode.sh` | JWT parsing and payload extraction |
| `jwt_forge.py` | JWT creation with algorithm confusion |
| `ssrf_payload_gen.sh` | SSRF payload template generation |

---

## Appendix C: References

### C.1 Vulnerability References

1. **CWE-200: Exposure of Sensitive Information**
   - https://cwe.mitre.org/data/definitions/200.html

2. **CWE-183: Permissive List of Allowed Inputs**
   - https://cwe.mitre.org/data/definitions/183.html

3. **CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes**
   - https://cwe.mitre.org/data/definitions/915.html

4. **CWE-918: Server-Side Request Forgery (SSRF)**
   - https://cwe.mitre.org/data/definitions/918.html

5. **CWE-345: Insufficient Verification of Data Authenticity**
   - https://cwe.mitre.org/data/definitions/345.html

### C.2 OWASP References

1. **OWASP API Security Top 10 (2023)**
   - API2:2023 - Broken Authentication
   - API3:2023 - Broken Object Property Level Authorization
   - API8:2023 - Security Misconfiguration
   - API10:2023 - Unsafe Consumption of APIs

2. **OWASP Testing Guide v4**
   - Information Gathering
   - Configuration and Deployment Management Testing
   - Identity Management Testing
   - Authentication Testing
   - Authorization Testing

### C.3 CWE References

1. **OWASP Mass Assignment Cheat Sheet**
   - https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html

2. **OWASP GraphQL Cheat Sheet**
   - https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html

3. **OWASP JWT Cheat Sheet**
   - https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html

### C.4 Industry References

1. **MITRE ATT&CK Framework**
   - Enterprise Matrix: https://attack.mitre.org/matrices/enterprise/

2. **NIST SP 800-53 Rev 5**
   - Security and Privacy Controls for Information Systems and Organizations

3. **AWS Security Best Practices**
   - IMDSv2: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html

---

## Appendix D: Vulnerability Disclosure Timeline

| Date | Action | Details |
|------|--------|---------|
| May 4, 2026 | Assessment Commenced | Initial reconnaissance and enumeration |
| May 4, 2026 | V-01 Discovered | GraphQL introspection identified |
| May 4, 2026 | V-02 Discovered | OAuth redirect validation flaw identified |
| May 5, 2026 | V-03 Discovered | Mass assignment vulnerability identified |
| May 5, 2026 | V-04 Discovered | SSRF in document generation identified |
| May 5, 2026 | V-05 Discovered | JWT algorithm confusion identified |
| May 5, 2026 | Assessment Complete | All findings documented |
| May 5, 2026 | Report Delivered | Findings presented to client |

---

## Appendix E: Glossary

| Term | Definition |
|------|------------|
| **API** | Application Programming Interface |
| **BOPLA** | Broken Object Property Level Authorization |
| **CORS** | Cross-Origin Resource Sharing |
| **CSRF** | Cross-Site Request Forgery |
| **CVE** | Common Vulnerabilities and Exposures |
| **CWE** | Common Weakness Enumeration |
| **CVSS** | Common Vulnerability Scoring System |
| **GraphQL** | Query language for APIs |
| **HMAC** | Hash-based Message Authentication Code |
| **HS256** | HMAC with SHA-256 |
| **IAM** | Identity and Access Management |
| **IMDS** | Instance Metadata Service |
| **JWT** | JSON Web Token |
| **JWKS** | JSON Web Key Set |
| **OAuth** | Open Authorization framework |
| **OWASP** | Open Web Application Security Project |
| **PDF** | Portable Document Format |
| **PKCE** | Proof Key for Code Exchange |
| **REST** | Representational State Transfer |
| **RS256** | RSA Signature with SHA-256 |
| **SSRF** | Server-Side Request Forgery |
| **TTP** | Tactics, Techniques, and Procedures |

---

## Appendix F: Assessment Team

| Role | Responsibility |
|------|----------------|
| **Lead Assessor** | Primary vulnerability discovery and exploitation |
| **Report Author** | Documentation and deliverable preparation |
| **Quality Reviewer** | Technical accuracy verification |

---

## Appendix G: Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | May 5, 2026 | Assessment Team | Initial release |

**Document Classification:** Confidential  
**Distribution:** Client Security Team, CISO Office  

---

*This report contains confidential information regarding the security posture of the assessed organization. Distribution should be limited to authorized personnel with a legitimate need to access the findings.*
