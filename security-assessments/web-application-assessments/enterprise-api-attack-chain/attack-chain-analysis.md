
# Attack Chain Analysis & Kill Chain Mapping

## Executive Overview

This document provides a detailed analysis of the complete attack chain demonstrated during the assessment. The chain comprises five distinct but interdependent vulnerabilities that, when exploited sequentially, enable an external attacker to progress from unauthenticated reconnaissance to full compromise of the internal secrets management system. Each stage is mapped to industry-standard frameworks including MITRE ATT&CK and the Lockheed Martin Cyber Kill Chain to facilitate detection engineering and defensive improvements.

---

## Attack Chain Visualization

### Stage 1: Reconnaissance & Information Gathering *(T+0.0h – T+1.5h)*

- **Port scanning** → None → Service map discovered
- **Directory enumeration** → None → Endpoint list identified
- **Technology fingerprinting** → None → Technology stack documented

### Stage 2: Initial Access & Credential Discovery *(T+1.5h – T+3.5h)*

- **GraphQL introspection** → None → Complete API schema mapped
- **debugInfo query** → None → JWT initialization token extracted
- **Internal endpoint discovery** → None → Internal service addresses exposed

### Stage 3: Authentication Bypass *(T+3.5h – T+5.0h)*

- **OAuth startsWith() validation flaw** → None → Authorization code captured
- **Token exchange** → None → Employee-level session acquired
- **Identity verification** → Employee → Low-privileged access confirmed

### Stage 4: Privilege Escalation *(T+5.0h – T+7.0h)*

- **REST API mass assignment** → Employee → Administrative role self-assigned
- **Role injection** → Admin → Super-admin privileges obtained
- **Authorization control bypass** → Super-admin → Full system control

### Stage 5: Internal Network Penetration *(T+7.0h – T+9.0h)*

- **SSRF via PDF generation engine** → Super-admin → Cloud metadata service accessed
- **Metadata credential extraction** → Vault-adjacent → AWS IAM credentials retrieved
- **JWKS endpoint retrieval** → Vault-adjacent → RSA public key material acquired

### Stage 6: Cryptographic Bypass & Data Exfiltration *(T+9.0h – T+10.0h)*

- **JWT algorithm confusion attack** → Vault-adjacent → Super-admin token forged
- **Vault access with forged token** → Vault compromise → Database credentials exposed
- **Secrets extraction** → Vault compromise → Cloud root keys and API signing keys obtained

---

**Total Time to Full Compromise: 10 hours**  
**Vulnerabilities Exploited: 5 (chained)**  
**Final Access Level: Complete internal vault compromise**
text


---

## Stage 1: Reconnaissance & Information Gathering

### Timeline: T+0h to T+1.5h

### MITRE ATT&CK Mapping

| Tactic | Technique | ID | Description |
|--------|-----------|----|-------------|
| Reconnaissance | Active Scanning | T1595 | Port scanning and service discovery |
| Reconnaissance | Gather Victim Host Information | T1592 | Technology fingerprinting |
| Discovery | Network Service Discovery | T1046 | Identifying running services |
| Discovery | Application Layer Protocol: Web Protocols | T1071.001 | HTTP/HTTPS enumeration |

### Cyber Kill Chain Phase: Reconnaissance

**Tools and Techniques Used:**

1. **Network Discovery (T+0h to T+0.3h):**
   - ICMP ping sweep to verify host reachability
   - TCP SYN scan (`nmap -sS -sV -sC`) to identify open ports and services
   - Service version detection to identify Express.js framework

2. **Application Enumeration (T+0.3h to T+1.0h):**
   - HTTP response header analysis revealing `X-Powered-By: Express`
   - Directory brute-force enumeration using custom wordlist
   - Endpoint discovery via common API path patterns

3. **Technology Stack Identification (T+1.0h to T+1.5h):**
   - CORS header analysis (`Access-Control-Allow-Origin: *`)
   - Content-Security-Policy review
   - GraphQL endpoint identification via distinctive 400 error response

**Key Discovery:**
The `/api/graphql` endpoint returning `{"errors":[{"message":"Query is required"}]}` confirmed a GraphQL server, leading to introspection exploitation.

### Defensive Opportunities

- **Detection:** Monitor for rapid sequential requests to non-existent paths (directory enumeration)
- **Prevention:** Disable technology stack disclosure headers
- **Hunting:** Look for nmap scan patterns in network logs

---

## Stage 2: Credential & Token Acquisition

### Timeline: T+1.5h to T+3.5h

### MITRE ATT&CK Mapping

| Tactic | Technique | ID | Description |
|--------|-----------|----|-------------|
| Credential Access | Unsecured Credentials | T1552 | Exposed debug tokens in API response |
| Credential Access | Exploit Public-Facing Application | T1190 | GraphQL introspection abuse |
| Initial Access | Valid Accounts | T1078 | OAuth token acquisition |

### Cyber Kill Chain Phase: Weaponization & Delivery

**Exploitation Sequence:**

1. **GraphQL Schema Enumeration (T+1.5h to T+2.0h):**

Request: POST /api/graphql
Body: {__schema{types{name,fields{name}}}}
Result: Complete API type/query/mutation map
text


2. **Sensitive Endpoint Discovery (T+2.0h to T+2.5h):**
- Identified `DebugInfo` type with fields: `recon_token`, `internalEndpoints`
- Queried unauthenticated `debugInfo` query
- Retrieved valid JWT with purpose `oauth_init`
- Retrieved internal infrastructure details

3. **OAuth Flow Analysis (T+2.5h to T+3.0h):**
- Discovered `/oauth/authorize` endpoint
- Extracted `client_id` from frontend JavaScript bundle
- Tested redirect_uri validation logic

4. **Authorization Code Capture (T+3.0h to T+3.5h):**
- Crafted bypass redirect URI exploiting `startsWith()` validation
- Exchanged authorization code for access token
- Authenticated as low-privileged employee user

**Data Exfiltrated:**
- OAuth initialization JWT token
- Internal vault service address
- Cloud metadata endpoint
- Employee-level access token

### Defensive Opportunities

- **Prevention:** Disable GraphQL introspection in production
- **Detection:** Monitor for GraphQL introspection queries (pattern: `__schema`)
- **Hunting:** Alert on successful OAuth flows with non-registered redirect_uri patterns
- **Hardening:** Implement PKCE extension for OAuth 2.0

---

## Stage 3: Privilege Escalation

### Timeline: T+3.5h to T+5.0h

### MITRE ATT&CK Mapping

| Tactic | Technique | ID | Description |
|--------|-----------|----|-------------|
| Privilege Escalation | Abuse Elevation Control Mechanism | T1548 | Bypassing role-based access control |
| Defense Evasion | Modify Authentication Process | T1556 | Self-modification of authorization attributes |
| Persistence | Account Manipulation | T1098 | Elevation of own account privileges |

### Cyber Kill Chain Phase: Exploitation & Installation

**Exploitation Sequence:**

1. **User Enumeration (T+3.5h to T+4.0h):**

Query: {users{id,email,role,permissions}}
Result: Discovered admin user (ID: 1001) and our employee account (ID: 1003)
text


2. **GraphQL Restriction Discovery (T+4.0h to T+4.3h):**
- Attempted `promoteUser` mutation → "Forbidden"
- Confirmed proper authorization on GraphQL mutations
- Pivoted to alternative API surface

3. **REST API Discovery (T+4.3h to T+4.6h):**
- Analyzed frontend bundle for API endpoints
- Found `PUT /api/v2/users/me` endpoint
- Identified lack of field-level filtering

4. **Mass Assignment Exploitation (T+4.6h to T+5.0h):**

Request: PUT /api/v2/users/me
Body: {"role":"admin","permissions":["read","write","admin"]}
Result: Immediate role escalation to administrator

Request: PUT /api/v2/users/me
Body: {"role":"super-admin","permissions":[...]}
Result: Escalation to super-administrator
text


**Privilege Transition:**

Employee (read-only) → Admin (read/write/admin) → Super-admin (full control)
text


### Defensive Opportunities

- **Prevention:** Implement field-level allowlisting on all API endpoints
- **Detection:** Alert on modifications to sensitive user attributes (role, permissions)
- **Hunting:** Review access logs for PUT requests to user profile endpoints containing unexpected fields
- **Architecture:** Separate user profile management from permission management

---

## Stage 4: Internal Network Penetration

### Timeline: T+5.0h to T+7.0h

### MITRE ATT&CK Mapping

| Tactic | Technique | ID | Description |
|--------|-----------|----|-------------|
| Discovery | Cloud Service Discovery | T1526 | Cloud metadata service access |
| Collection | Data from Cloud Storage Object | T1530 | Credential extraction from metadata |
| Lateral Movement | Remote Services: Cloud Metadata | T1021.007 | SSRF to internal cloud endpoint |
| Credential Access | Unsecured Credentials: Cloud Metadata API | T1552.005 | IAM credential theft |

### Cyber Kill Chain Phase: Command & Control / Actions on Objectives

**Exploitation Sequence:**

1. **Admin Feature Discovery (T+5.0h to T+5.5h):**
   - Identified document generation feature in admin panel
   - Discovered HTML template rendering capability
   - Confirmed server-side JavaScript execution

2. **SSRF Payload Development (T+5.5h to T+6.0h):**
   ```html
   <script>
   fetch("http://169.254.169.254/latest/meta-data/")
     .then(r => r.text())
     .then(t => document.write(t))
   </script>

    Cloud Metadata Enumeration (T+6.0h to T+6.5h):
    text

    Request: POST /api/v2/reports/generate
    Body: {"template":"<script>fetch(\"http://169.254.169.254/...\")</script>"}
    Response: rendering_log containing metadata service response body

    IAM Credential Extraction (T+6.5h to T+7.0h):

        Retrieved IAM role credentials from metadata

        Obtained AccessKeyId, SecretAccessKey, and SessionToken

        Discovered JWKS endpoint URL for authentication service

Network Boundaries Bypassed:
text

Internet → Application Server (SSRF) → 169.254.169.254 (Cloud Metadata)
                                     → internal-vault (8200/tcp)
                                     → auth service (1337/tcp)

Defensive Opportunities

    Prevention: Block outbound requests to 169.254.169.254 at application and network level

    Detection: Monitor for HTML/JavaScript in document template submissions

    Hunting: Alert on SSRF response logging containing metadata service paths

    Architecture: Use IMDSv2 (metadata service v2) requiring session tokens

Stage 5: Cryptographic Bypass & Data Exfiltration
Timeline: T+7.0h to T+10.0h
MITRE ATT&CK Mapping
Tactic	Technique	ID	Description
Credential Access	Steal Application Access Token	T1528	JWT token forgery
Defense Evasion	Subvert Trust Controls	T1553	Cryptographic algorithm confusion
Collection	Data from Information Repositories: Vault	T1213	Secrets extraction
Exfiltration	Exfiltration Over Web Service	T1567	Data extraction through API
Cyber Kill Chain Phase: Actions on Objectives

Exploitation Sequence:

    JWKS Retrieval (T+7.0h to T+7.5h):
    text

    Request: GET /.well-known/jwks.json
    Response: RSA public key (n, e, x5c certificate)

    Vulnerability Analysis (T+7.5h to T+8.0h):

        Identified server accepts alg header from client

        Confirmed HS256 verification uses RSA public key as HMAC secret

        Recognized classic JWT algorithm confusion pattern

    Token Forgery (T+8.0h to T+8.5h):
    python

    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"role": "super-admin", "sub": "forged"}
    signature = HMAC-SHA256(public_key, header.payload)

    Vault Compromise (T+8.5h to T+9.0h):
    text

    Request: GET /api/vault/critical-secrets
    Authorization: Bearer <forged-super-admin-token>
    Response: Complete vault contents

    Data Exfiltration (T+9.0h to T+10.0h):

        Database master credentials

        Cloud provider root access keys

        Internal API signing keys

Trust Model Subverted:
text

Server expects: Client proves identity via JWT signed with private key
Attacker provides: Forged JWT signed with public key treated as shared secret
Server verifies: Signature matches (using public key as HMAC key)
Result: Server trusts attacker as super-admin

Defensive Opportunities

    Prevention: Explicitly restrict JWT algorithms in verification library

    Detection: Alert on JWT tokens with unexpected algorithm claims

    Hunting: Look for HS256 tokens when only RS256 is configured

    Architecture: Use opaque tokens or separate key stores for signing
    

## Attack Chain Dependency Map

### Vulnerability Dependencies

**V-01 – GraphQL Introspection**
- **Provides:** `recon_token` (JWT) → Required by: V-02 (OAuth Bypass)
- **Provides:** `internalEndpoints` → Required by: V-04 (SSRF), V-05 (JWKS)

**V-02 – OAuth Redirect Bypass**
- **Provides:** `access_token` (employee) → Required by: V-03 (Mass Assignment)

**V-03 – Mass Assignment**
- **Provides:** Super-admin privileges → Required by: V-04 (SSRF via admin endpoint)

**V-04 – Blind SSRF**
- **Provides:** Cloud IAM credentials → Required by: Direct cloud access
- **Provides:** JWKS endpoint URL → Required by: V-05 (JWT Confusion)

**V-05 – JWT Algorithm Confusion**
- **Provides:** Vault access (super-admin token) → Required by: Final objective completion

### Elimination Analysis

| If This Is Fixed | Attack Stops At | Rationale |
|------------------|-----------------|-----------|
| **V-01** | Stage 1 | No token, no internal endpoints discovered |
| **V-02** | Stage 2 | No valid session token obtainable |
| **V-03** | Stage 3 | No administrative access achievable |
| **V-04** | Stage 4† | Attack may continue via alternative JWKS discovery |
| **V-05** | Stage 5 | Cannot forge tokens; vault remains protected |

*† V-04 provides one path to the JWKS endpoint. Alternative discovery methods may exist.*

---

## Detection Engineering Recommendations

### Log Sources for Attack Detection

| Stage | Log Source | Event to Monitor | SIEM Rule Suggestion |
|-------|-----------|------------------|---------------------|
| **1** | Web Server Access Logs | Rapid 404 responses from single IP | Rate limiting alert |
| **1** | GraphQL Server | Introspection queries (`__schema`) | Block and alert on introspection |
| **2** | OAuth Server | Non-standard `redirect_uri` patterns | Alert on `startsWith`-like bypass attempts |
| **3** | API Gateway | PUT requests containing `role` field | Alert on sensitive field modifications |
| **3** | Database Audit Log | User role modifications | Alert on unauthorized role changes |
| **4** | Application Logs | Template content with `<script>` tags | Alert on JavaScript in templates |
| **4** | Network Firewall | Outbound connections to `169.254.169.254` | Block and alert immediately |
| **5** | Authentication Service | JWT with unexpected `alg` header | Alert on HS256 when RS256 expected |
| **5** | Vault Audit Log | Unusual access patterns to critical secrets | Alert on bulk secret access |

### Suggested SIEM Correlation Rule

**Rule Name:** Potential Attack Chain in Progress  
**Severity:** Critical  
**Logic:**

1. GraphQL Introspection Detection → within 2 hours
2. → OAuth Anomaly Detected → within 2 hours
3. → User Role Modification → within 2 hours
4. → SSRF to Metadata Service OR Vault Access

**Action:** Immediate security team escalation and incident response activation

---

## MITRE ATT&CK Navigator Layer

### Technique Mapping

| Stage | Technique ID | Technique Name | Description |
|-------|-------------|----------------|-------------|
| **1** | T1595 | Active Scanning | Network and service discovery |
| **1-2** | T1190 | Exploit Public-Facing Application | GraphQL introspection abuse |
| **1-2** | T1552 | Unsecured Credentials | Debug tokens in API responses |
| **2** | T1078 | Valid Accounts | OAuth session acquisition |
| **3** | T1548 | Abuse Elevation Control Mechanism | Mass assignment privilege escalation |
| **3** | T1098 | Account Manipulation | Role injection via API |
| **4** | T1526 | Cloud Service Discovery | Metadata service enumeration |
| **4** | T1552.005 | Cloud Metadata API | IAM credential extraction |
| **5** | T1528 | Steal Application Access Token | JWT token forgery |
| **5** | T1553 | Subvert Trust Controls | Cryptographic algorithm confusion |
| **5** | T1213 | Data from Information Repositories | Vault secrets extraction |

### Navigator Layer JSON

The complete MITRE ATT&CK Navigator layer is available as a standalone JSON file for direct import into the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) web tool.

📄 **[Download: mitre-attack-layer.json](mitre-attack-layer.json)**

<details>
<summary>Click to view raw JSON</summary>

```json
{
  "name": "Enterprise API Attack Chain Assessment",
  "domain": "enterprise-attack",
  "versions": {
    "attack": "15",
    "navigator": "4.9.0",
    "layer": "4.5"
  },
  "techniques": [
    {"techniqueID": "T1595", "score": 100, "comment": "Stage 1: Active scanning"},
    {"techniqueID": "T1190", "score": 100, "comment": "Stage 1: GraphQL introspection"},
    {"techniqueID": "T1552", "score": 100, "comment": "Stage 1: Unsecured debug tokens"},
    {"techniqueID": "T1078", "score": 80, "comment": "Stage 2: OAuth session acquisition"},
    {"techniqueID": "T1548", "score": 100, "comment": "Stage 3: Mass assignment escalation"},
    {"techniqueID": "T1098", "score": 100, "comment": "Stage 3: Account manipulation"},
    {"techniqueID": "T1526", "score": 100, "comment": "Stage 4: Cloud metadata discovery"},
    {"techniqueID": "T1552.005", "score": 100, "comment": "Stage 4: IAM credential theft"},
    {"techniqueID": "T1528", "score": 100, "comment": "Stage 5: JWT token forgery"},
    {"techniqueID": "T1553", "score": 100, "comment": "Stage 5: Cryptographic trust subversion"},
    {"techniqueID": "T1213", "score": 100, "comment": "Stage 5: Vault secrets extraction"}
  ]
}

```
</details>

---

*This attack chain analysis provides a comprehensive view of the tactics, techniques, and procedures demonstrated during the assessment. It should be used to inform defensive improvements and detection engineering efforts.*
