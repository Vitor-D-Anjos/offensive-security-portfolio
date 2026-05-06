
# Regulatory Compliance Mapping

## Overview

This appendix maps the identified vulnerabilities to applicable regulatory frameworks and industry standards. Each finding is cross-referenced to specific control requirements, enabling the organization to assess compliance impact and prioritize remediation within their governance, risk, and compliance (GRC) programs.

---

## Framework Cross-Reference Matrix

| Finding | Severity | PCI-DSS v4.0 | SOC 2 (CC) | ISO 27001:2022 | NIST 800-53 Rev 5 | HIPAA | GDPR |
|---------|----------|--------------|------------|----------------|-------------------|-------|------|
| V-01: GraphQL Introspection | High | 6.2.4, 6.5.8 | CC6.1, CC6.6 | A.8.9, A.8.16 | AC-3, SI-11 | §164.312(e)(1) | Art. 25, 32 |
| V-02: OAuth redirect_uri Bypass | Medium | 6.2.4, 7.2.1 | CC6.1, CC6.3 | A.8.1, A.8.5 | AC-3, IA-2 | §164.312(d) | Art. 25, 32 |
| V-03: Mass Assignment (Priv Esc) | Critical | 6.2.4, 7.1.2, 7.2.2 | CC6.1, CC6.3, CC6.6 | A.8.2, A.8.9, A.8.16 | AC-3, AC-6, AU-2 | §164.312(a)(1) | Art. 25, 32 |
| V-04: Blind SSRF (Metadata Access) | Critical | 6.2.4, 7.1.2 | CC6.1, CC6.6 | A.8.9, A.8.16, A.8.22 | AC-3, SC-7, SI-11 | §164.312(e)(1) | Art. 25, 32 |
| V-05: JWT Algorithm Confusion | Critical | 6.2.4, 7.1.2, 7.2.2 | CC6.1, CC6.3 | A.8.1, A.8.5, A.8.16 | IA-2, IA-5, IA-8 | §164.312(d) | Art. 25, 32 |

---

## PCI-DSS v4.0 Mapping

### Applicability

As a cloud application handling customer data and processing payments through integrated services, the organization is subject to PCI-DSS requirements for systems within the cardholder data environment (CDE).

### Requirement Mapping

#### Requirement 6: Develop and Maintain Secure Systems and Software

| Requirement | Description | Impacted Findings | Compliance Status |
|-------------|-------------|-------------------|-------------------|
| **6.2.4** | Software engineering techniques and security automation for all technology stacks | V-01, V-02, V-03, V-04, V-05 | **Non-Compliant** |
| **6.5.8** | Protection against incomplete input validation | V-01, V-03 | **Non-Compliant** |

**Requirement 6.2.4 Detail:**
> "Software engineering techniques and security automation are used for all technology stacks..."

**Compliance Gap:** The following software engineering techniques were absent:
- GraphQL query complexity analysis (V-01)
- Input field allowlisting in REST endpoints (V-03)
- URL validation for server-side requests (V-04)
- Algorithm restriction in JWT verification (V-05)

**Remediation:** Implement the code-level fixes documented in Section 03-Findings-and-Remediations.md for each finding.

#### Requirement 7: Restrict Access to System Components and Cardholder Data by Business Need to Know

| Requirement | Description | Impacted Findings | Compliance Status |
|-------------|-------------|-------------------|-------------------|
| **7.1.2** | Access control mechanisms enforced for all user accounts | V-03, V-04, V-05 | **Non-Compliant** |
| **7.2.1** | Access control systems applied to all system components | V-02 | **Non-Compliant** |
| **7.2.2** | Access assigned based on individual personnel needs | V-03, V-05 | **Non-Compliant** |

**Requirement 7.2.2 Detail:**
> "Access is assigned to users based on their job classification and function..."

**Compliance Gap:** The mass assignment vulnerability (V-03) allowed any authenticated user to self-assign administrative privileges, completely bypassing role-based access controls. The JWT algorithm confusion (V-05) allowed token forgery with arbitrary role claims.

**Remediation:** Implement field-level allowlisting on user profile endpoints and explicit algorithm restriction on JWT verification.

### PCI-DSS Compliance Impact Summary

| Impact Level | Description |
|--------------|-------------|
| **Immediate Risk** | Findings V-03 and V-05 directly violate PCI-DSS access control requirements and could result in a failed assessment |
| **Remediation Priority** | Critical findings must be addressed before the next PCI assessment cycle |
| **Compensating Controls** | Until fixed, implement WAF rules blocking mass assignment patterns and SIEM alerts for unexpected role changes |

---

## SOC 2 Common Criteria Mapping

### Applicability

SOC 2 applies to service organizations storing, processing, or transmitting customer data. The Trust Services Criteria (TSC) most impacted are Security (Common Criteria) and, depending on data sensitivity, Confidentiality and Privacy.

### Trust Services Criteria Mapping

#### CC6.1: Logical and Physical Access Controls

| Criterion | Description | Impacted Findings |
|-----------|-------------|-------------------|
| **CC6.1** | The entity implements logical access security measures to protect against unauthorized access | V-01, V-02, V-03, V-04, V-05 |

**Compliance Gap Detail:**
> "Logical access security software, infrastructure, and architectures have been implemented..."

The assessment demonstrated that:
1. Unauthenticated users could enumerate the complete API schema (V-01)
2. OAuth authorization codes could be obtained through redirect bypass (V-02)
3. Low-privileged users could self-escalate to super-admin (V-03)
4. Internal network resources were accessible from the application tier (V-04)
5. Authentication tokens could be forged using public key material (V-05)

**Impact on SOC 2 Report:** These findings would result in a **qualified opinion** or **adverse opinion** in a SOC 2 Type II assessment, depending on severity and duration of exposure.

#### CC6.3: Access Provisioning and Deprovisioning

| Criterion | Description | Impacted Findings |
|-----------|-------------|-------------------|
| **CC6.3** | The entity authorizes, modifies, and removes access based on role-based access controls | V-02, V-03, V-05 |

**Compliance Gap Detail:**
> "The entity creates, updates, and removes access to systems, applications, and data..."

The mass assignment vulnerability (V-03) allowed self-service role modification without administrative approval. The JWT confusion attack (V-05) enabled complete bypass of the role assignment process.

#### CC6.6: Security Measures Against External Threats

| Criterion | Description | Impacted Findings |
|-----------|-------------|-------------------|
| **CC6.6** | The entity implements controls to protect against external threats | V-01, V-03, V-04 |

**Compliance Gap Detail:**
> "The entity implements detection, prevention, and response controls to protect against threats..."

The exposed GraphQL introspection (V-01) provided attackers with a complete API blueprint. The SSRF vulnerability (V-04) allowed access to cloud instance metadata from external entry points.

---

## ISO 27001:2022 Mapping

### Applicability

ISO 27001 provides requirements for an Information Security Management System (ISMS). The following Annex A controls are impacted.

### Control Mapping

#### A.8: Technological Controls

| Control | Title | Impacted Findings | Compliance Status |
|---------|-------|-------------------|-------------------|
| **A.8.1** | User endpoint devices | V-02, V-05 | **Non-Compliant** |
| **A.8.2** | Privileged access rights | V-03, V-05 | **Non-Compliant** |
| **A.8.5** | Secure authentication | V-02, V-05 | **Non-Compliant** |
| **A.8.9** | Configuration management | V-01, V-03, V-04 | **Non-Compliant** |
| **A.8.16** | Monitoring activities | V-01, V-03, V-04, V-05 | **Non-Compliant** |
| **A.8.22** | Web filtering | V-04 | **Partially Compliant** |

#### Control A.8.9: Configuration Management

> "Configurations (including security configurations) of hardware, software, services and networks should be established, documented, implemented, monitored and reviewed."

**Non-Compliance Evidence:**
| Configuration Issue | Finding | Standard Requirement |
|--------------------|---------|---------------------|
| GraphQL introspection enabled in production | V-01 | Security hardening standards not applied to production deployments |
| REST API endpoint without field filtering | V-03 | Input validation configuration not documented or implemented |
| Puppeteer without network restrictions | V-04 | Service configuration allows unrestricted outbound access |

#### Control A.8.2: Privileged Access Rights

> "The allocation and use of privileged access rights should be restricted and controlled."

**Non-Compliance Evidence:**
| Access Control Failure | Finding | Impact |
|------------------------|---------|--------|
| Self-service role modification | V-03 | Any user can grant themselves administrative privileges |
| Token forgery capability | V-05 | Attacker can create tokens for any privilege level without detection |

---

## NIST SP 800-53 Rev 5 Mapping

### Applicability

For organizations aligned with the NIST Risk Management Framework (RMF) or required to comply with NIST standards for federal systems.

### Control Family Mapping

#### Access Control (AC)

| Control | Title | Impacted Findings | Assessment |
|---------|-------|-------------------|------------|
| **AC-3** | Access Enforcement | V-01, V-02, V-03, V-04 | **Failed** |
| **AC-6** | Least Privilege | V-03 | **Failed** |

**AC-3 Assessment Detail:**
> "The information system enforces approved authorizations for logical access to information and system resources..."

The assessment demonstrated multiple access enforcement failures:
- V-01: Unauthenticated access to sensitive debug information
- V-02: OAuth authorization code interception via redirect bypass
- V-03: Self-service privilege escalation bypassing role hierarchy
- V-04: Internal network access from external entry point

**AC-6 Assessment Detail:**
> "The organization employs the principle of least privilege..."

The mass assignment vulnerability (V-03) enabling employee-to-super-admin escalation represents a complete failure of least privilege enforcement.

#### Identification and Authentication (IA)

| Control | Title | Impacted Findings | Assessment |
|---------|-------|-------------------|------------|
| **IA-2** | Identification and Authentication (Organizational Users) | V-02, V-05 | **Failed** |
| **IA-5** | Authenticator Management | V-05 | **Failed** |
| **IA-8** | Identification and Authentication (Non-Organizational Users) | V-05 | **Failed** |

**IA-2 Assessment Detail:**
> "The information system uniquely identifies and authenticates organizational users..."

The JWT algorithm confusion (V-05) enables token forgery for any user, completely undermining the identification and authentication mechanism.

#### System and Communications Protection (SC)

| Control | Title | Impacted Findings | Assessment |
|---------|-------|-------------------|------------|
| **SC-7** | Boundary Protection | V-04 | **Failed** |

**SC-7 Assessment Detail:**
> "The information system monitors and controls communications at the external boundary..."

The SSRF vulnerability (V-04) allowed the application server to access the cloud metadata service (169.254.169.254) and internal vault service, bypassing network boundary controls.

#### System and Information Integrity (SI)

| Control | Title | Impacted Findings | Assessment |
|---------|-------|-------------------|------------|
| **SI-11** | Error Handling | V-01, V-03, V-04 | **Failed** |

---

## HIPAA Security Rule Mapping

### Applicability

If the application processes, stores, or transmits Protected Health Information (PHI), HIPAA Security Rule requirements apply.

### Safeguard Mapping

| Citation | Safeguard | Description | Impacted Findings |
|----------|-----------|-------------|-------------------|
| **§164.312(a)(1)** | Access Control | Unique user identification and emergency access procedures | V-03, V-05 |
| **§164.312(d)** | Person or Entity Authentication | Verify that persons seeking access are who they claim to be | V-02, V-05 |
| **§164.312(e)(1)** | Transmission Security | Protect against unauthorized access during transmission | V-01, V-04 |

### Compliance Impact

| Finding | HIPAA Impact |
|---------|--------------|
| V-03 + V-05 | Complete failure of access controls and authentication—would result in **willful neglect** finding if PHI were exposed |
| V-01 + V-04 | Technical safeguards for transmission and access control not adequately implemented |

**Potential Consequence:** Category 4 violation (willful neglect—not corrected) carries maximum penalty of **$1.5 million per violation category per year** under HIPAA Enforcement Rule.

---

## GDPR Mapping

### Applicability

If the application processes personal data of EU/UK residents, GDPR requirements apply regardless of the organization's geographic location.

### Article Mapping

| Article | Requirement | Impacted Findings |
|---------|-------------|-------------------|
| **Art. 25** | Data protection by design and by default | All findings (V-01 through V-05) |
| **Art. 32** | Security of processing | All findings (V-01 through V-05) |
| **Art. 33** | Notification of personal data breach to supervisory authority | Applicable if data breach confirmed |
| **Art. 34** | Communication of personal data breach to data subjects | Applicable if high risk to individuals |

### Article 25 Assessment

> "Taking into account the state of the art, the cost of implementation and the nature, scope, context and purposes of processing... the controller shall implement appropriate technical and organisational measures..."

**Compliance Gap:** The following data protection by design principles were not implemented:

| Principle | Finding | Gap Description |
|-----------|---------|-----------------|
| Input validation by default | V-03 | API endpoints accept arbitrary fields without filtering |
| Least privilege by default | V-03 | Users can self-assign administrative roles |
| Secure defaults | V-01 | GraphQL introspection enabled in production environment |
| Defense in depth | V-04, V-05 | No secondary controls preventing SSRF or token forgery |

### Article 32 Assessment

> "...the controller and the processor shall implement appropriate technical and organisational measures to ensure a level of security appropriate to the risk..."

**Compliance Gap:** All five findings represent failures of appropriate technical measures. The combination of these vulnerabilities creating a complete attack chain from external access to full data compromise demonstrates systematic security control inadequacy.

### Breach Notification Impact

If personal data was actually compromised through these vulnerabilities:

| Requirement | Timeline | Authority |
|-------------|----------|-----------|
| **Supervisory Authority Notification** | Within 72 hours of discovery | ICO (UK), DPC (Ireland), etc. |
| **Data Subject Notification** | Without undue delay | Affected individuals |
| **Documentation** | Maintain records of breach and response | Internal GRC |

**Potential Penalty:** Up to **€20 million or 4% of annual global turnover**, whichever is higher (Art. 83(5)).

---

## OWASP Mapping

### OWASP API Security Top 10 (2023)

| Finding | OWASP API Category | Risk Rating |
|---------|-------------------|-------------|
| V-01 | API2:2023 - Broken Authentication (Information Leakage) | High |
| V-02 | API8:2023 - Security Misconfiguration | Medium |
| V-03 | API3:2023 - Broken Object Property Level Authorization | Critical |
| V-04 | API10:2023 - Unsafe Consumption of APIs | Critical |
| V-05 | API2:2023 - Broken Authentication | Critical |

### OWASP Web Application Top 10 (2021)

| Finding | OWASP Category |
|---------|----------------|
| V-01 | A01:2021 - Broken Access Control (Information Disclosure) |
| V-02 | A01:2021 - Broken Access Control |
| V-03 | A01:2021 - Broken Access Control |
| V-04 | A10:2021 - Server-Side Request Forgery (SSRF) |
| V-05 | A02:2021 - Cryptographic Failures |

---

## Compliance Remediation Priority Matrix

| Priority | Finding | Frameworks Impacted | Remediation Timeline |
|----------|---------|---------------------|---------------------|
| **P1 - Critical** | V-03 (Mass Assignment) | PCI-DSS 7.1.2, SOC 2 CC6.3, ISO A.8.2, NIST AC-6, HIPAA §164.312(a) | Within 24 hours |
| **P1 - Critical** | V-05 (JWT Confusion) | PCI-DSS 7.2.2, SOC 2 CC6.3, ISO A.8.5, NIST IA-2, HIPAA §164.312(d) | Within 24 hours |
| **P2 - High** | V-01 (GraphQL Introspection) | PCI-DSS 6.5.8, SOC 2 CC6.6, ISO A.8.9, HIPAA §164.312(e) | Within 48 hours |
| **P2 - High** | V-04 (Blind SSRF) | PCI-DSS 7.1.2, SOC 2 CC6.6, ISO A.8.16, NIST SC-7 | Within 1 week |
| **P3 - Medium** | V-02 (OAuth Bypass) | PCI-DSS 7.2.1, SOC 2 CC6.3, ISO A.8.1 | Within 1 week |

---

## Auditor Guidance

### Evidence to Prepare for Compliance Audits

| Framework | Required Evidence |
|-----------|-------------------|
| **PCI-DSS** | Remediation verification test results, updated configuration standards, WAF rule documentation |
| **SOC 2** | Updated access control policies, remediation change tickets, post-remediation penetration test results |
| **ISO 27001** | ISMS continuous improvement documentation, risk treatment plan updates, control effectiveness measurements |
| **HIPAA** | Risk assessment update, remediation plan with timelines, workforce retraining records |
| **GDPR** | Data protection impact assessment (DPIA) update, Article 32 compliance documentation, processor notification records |

### Sample Compliance Statement

> *"Following the penetration test conducted May 4-5, 2026, the organization identified five security findings impacting compliance with PCI-DSS v4.0, SOC 2 Trust Services Criteria, ISO 27001:2022 Annex A controls, and applicable data protection regulations. Critical findings V-03 and V-05 were remediated within 24 hours of discovery. All findings were resolved within the 14-day remediation window. A verification retest confirmed successful remediation. Updated control documentation and risk treatment plans have been filed with the GRC team."*

---

## References

1. **PCI Security Standards Council.** (2022). *PCI DSS v4.0*. https://www.pcisecuritystandards.org/
2. **AICPA.** (2022). *SOC 2 Trust Services Criteria*. https://www.aicpa.org/
3. **ISO/IEC.** (2022). *ISO/IEC 27001:2022 Information Security Management Systems*. https://www.iso.org/
4. **NIST.** (2020). *SP 800-53 Rev 5: Security and Privacy Controls for Information Systems and Organizations*. https://csrc.nist.gov/
5. **HHS.** (2013). *HIPAA Security Rule*. 45 CFR Part 160 and Subparts A and C of Part 164.
6. **European Union.** (2016). *General Data Protection Regulation (GDPR)*. Regulation (EU) 2016/679.

---

*This compliance mapping provides guidance for GRC integration. Specific compliance applicability should be confirmed by the organization's legal and compliance teams based on actual data processing activities and contractual obligations.*
