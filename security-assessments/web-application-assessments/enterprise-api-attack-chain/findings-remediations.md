
# Findings and Remediation Recommendations

## Finding Index

| ID | Title | Severity | CWE | CVSS |
|----|-------|----------|-----|------|
| V-01 | GraphQL Introspection Enabled in Production | High | CWE-200 | 7.5 |
| V-02 | OAuth redirect_uri Validation via startsWith() | Medium | CWE-183 | 6.5 |
| V-03 | Mass Assignment in User Profile API | Critical | CWE-915 | 9.8 |
| V-04 | Blind SSRF via Document Generation | Critical | CWE-918 | 9.1 |
| V-05 | JWT Algorithm Confusion Attack | Critical | CWE-345 | 9.8 |
| I-01 | Technology Stack Disclosure | Informational | CWE-200 | N/A |
| I-02 | Overly Permissive CORS Configuration | Informational | CWE-942 | N/A |

---

## V-01: GraphQL Introspection Enabled in Production

### Severity: High

### Description

The production GraphQL endpoint permits unauthenticated introspection queries, enabling complete schema enumeration including discovery of sensitive debug endpoints and internal token exposure.

### Affected Component

- **Path:** `/api/graphql`
- **Technology:** Apollo GraphQL Server

### Findings Detail

1. **Issue:** The Apollo Server `introspection` configuration option is set to `true` in the production environment.
2. **Exposure:** Unauthenticated queries to `__schema` meta-fields return complete API type definitions.
3. **Data Leakage:** The `debugInfo` query is accessible without authentication and returns internal tokens and service endpoints.

### Recommended Remediation

**Immediate Action (Priority: High):**

Disable introspection in production by configuring the Apollo Server:

```javascript
// Before (vulnerable)
const server = new ApolloServer({
    typeDefs,
    resolvers,
    introspection: true  // ← Remove or set to false
});

// After (secure)
const server = new ApolloServer({
    typeDefs,
    resolvers,
    introspection: process.env.NODE_ENV !== 'production'
});
```

Additional Hardening:

    Implement authentication on ALL queries, including meta-queries

    Add query complexity analysis to detect schema enumeration attempts

    Configure query depth limiting to prevent recursive introspection

Verification

After remediation, confirm that introspection queries return an error:
bash

$ curl -s http://target-app.local/api/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name}}}"}'
# Expected: {"errors":[{"message":"GraphQL introspection is not allowed"}]}

V-02: OAuth redirect_uri Validation via startsWith()
Severity: Medium
Description

The OAuth authorization endpoint validates the redirect_uri parameter using startsWith() string comparison rather than exact matching, allowing attackers to register callbacks at attacker-controlled domains.
Affected Component

    Path: /oauth/authorize

    Parameter: redirect_uri

Findings Detail

    Issue: Server-side validation uses redirectUri.startsWith(validPrefix) instead of redirectUri === validUri.

    Impact: URIs such as https://valid-prefix.attacker.com pass validation.

    Prerequisite: The valid redirect prefix is discoverable through application source analysis.

Recommended Remediation

Immediate Action (Priority: Medium):

Replace startsWith() with exact string matching:
javascript

// Before (vulnerable)
const VALID_REDIRECT = "https://app.target-app.local/callback";
function validateRedirect(uri) {
    return uri.startsWith(VALID_REDIRECT);  // ← Insecure
}

// After (secure)
const REGISTERED_REDIRECTS = [
    "https://app.target-app.local/callback",
    "https://app.target-app.local/callback/mobile"
];
function validateRedirect(uri) {
    return REGISTERED_REDIRECTS.includes(uri);  // ← Exact match
}

Additional Hardening:

    Implement PKCE (Proof Key for Code Exchange) for all OAuth flows

    Add state parameter validation to prevent CSRF attacks

    Consider using PAR (Pushed Authorization Requests) for additional security

Verification
bash

# Verify that bypass URIs are rejected
$ curl "http://target-app.local/oauth/authorize?\
client_id=app-client-production&\
redirect_uri=https://valid-prefix.attacker.com&\
response_type=code"
# Expected: {"error":"invalid_request","error_description":"Invalid redirect_uri"}

V-03: Mass Assignment in User Profile API
Severity: Critical
Description

The PUT /api/v2/users/me endpoint accepts arbitrary JSON fields and writes them to the database without filtering, allowing users to modify sensitive attributes including role and permissions.
Affected Component

    Path: /api/v2/users/me (PUT method)

    Technology: Express.js Router

Findings Detail

    Issue: The endpoint performs direct object assignment from request body to database.

    No Field Filtering: All JSON properties in the request body are accepted and persisted.

    Privilege Escalation: Any authenticated user can set their own role to admin or super-admin.

Recommended Remediation

Immediate Action (Priority: Critical):

Implement strict field allowlisting:
javascript

// Before (vulnerable)
app.put('/api/v2/users/me', authenticate, async (req, res) => {
    const updated = await User.update(req.user.id, req.body);  // ← All fields accepted
    res.json({ success: true, user: updated });
});

// After (secure)
const ALLOWED_UPDATE_FIELDS = ['displayName', 'email', 'avatar'];

app.put('/api/v2/users/me', authenticate, async (req, res) => {
    // Filter to only allowed fields
    const safeUpdates = {};
    for (const field of ALLOWED_UPDATE_FIELDS) {
        if (req.body[field] !== undefined) {
            safeUpdates[field] = req.body[field];
        }
    }
    
    const updated = await User.update(req.user.id, safeUpdates);
    res.json({ success: true, user: updated });
});

Additional Hardening:

    Use TypeScript or schema validation (Zod, Joi) to enforce strict input types

    Separate sensitive field updates to dedicated admin-only endpoints

    Implement audit logging for any role or permission changes

Verification
bash

# Verify that role injection is blocked
$ curl -s -X PUT http://target-app.local/api/v2/users/me \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TOKEN}" \
  -d '{"role":"admin"}'
# Expected: The "role" field should be silently dropped or explicitly rejected

V-04: Blind SSRF via Document Generation
Severity: Critical
Description

The administrative document generation feature executes JavaScript in HTML templates server-side, enabling interaction with internal network services including the cloud metadata endpoint.
Affected Component

    Path: /api/v2/reports/generate (POST method)

    Technology: Puppeteer (Headless Chromium)

Findings Detail

    Issue: HTML templates are rendered with full JavaScript execution in the server context.

    SSRF Vector: fetch() calls in template scripts can target internal services.

    Metadata Access: The cloud metadata service at 169.254.169.254 is reachable from the server.

Recommended Remediation

Immediate Action (Priority: Critical - within 1 week):

    Implement URL validation with a strict allowlist:

javascript

const ALLOWED_URLS = [
    'https://cdn.target-app.local/assets/',
    'https://api.target-app.local/public/'
];

function validateUrl(url) {
    return ALLOWED_URLS.some(allowed => url.startsWith(allowed));
}

    Block private IP ranges in outgoing requests:

javascript

const net = require('net');

function isPrivateIp(hostname) {
    // Block RFC 1918, loopback, and metadata IP
    const privateRanges = [
        /^127\./,
        /^10\./,
        /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
        /^192\.168\./,
        /^169\.254\./
    ];
    return privateRanges.some(range => range.test(hostname));
}

Additional Hardening:

    Disable JavaScript execution in the Puppeteer context unless specifically required

    Run document generation in an isolated container with no network access

    Implement network-level egress filtering on the application server

Verification
bash

# Verify metadata endpoint is blocked
$ curl -s -X POST http://target-app.local/api/v2/reports/generate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TOKEN}" \
  -d '{"template":"<script>fetch(\"http://169.254.169.254/\")</script>"}'
# Expected: rendering_log should show "blocked" or request should fail

V-05: JWT Algorithm Confusion Attack
Severity: Critical
Description

The JWT verification logic trusts the alg header from incoming tokens and uses the RSA public key as an HMAC secret when HS256 is specified, enabling token forgery with arbitrary claims.
Affected Component

    Authorization middleware

    JWKS endpoint: /.well-known/jwks.json

Findings Detail

    Issue: The token verification function accepts the algorithm from the JWT header without validation.

    Key Confusion: The RSA public key (available via JWKS) is used as an HMAC shared secret.

    Token Forgery: An attacker with the public key can create valid HS256 tokens with any claims.

Recommended Remediation

Immediate Action (Priority: Critical):

Explicitly restrict accepted JWT algorithms:
javascript

// Before (vulnerable)
function verifyToken(token) {
    const decoded = jwt.decode(token, { complete: true });
    const algorithm = decoded.header.alg;
    
    if (algorithm === 'RS256') {
        return jwt.verify(token, publicKey, { algorithms: ['RS256'] });
    } else if (algorithm === 'HS256') {
        return jwt.verify(token, publicKey, { algorithms: ['HS256'] });  // ← INSECURE
    }
}

// After (secure)
function verifyToken(token) {
    return jwt.verify(token, publicKey, { 
        algorithms: ['RS256'],  // ← Explicitly restrict to RS256 only
        issuer: 'https://auth.target-app.local',
        audience: 'app-production'
    });
}

Additional Hardening:

    Use separate keys for signing and verification, stored in separate locations

    Implement JWT claim validation (iss, aud, exp, nbf)

    Consider using opaque tokens with server-side validation instead of JWTs

    Rotate signing keys on a regular schedule

Verification
bash

# Verify HS256 tokens are rejected
$ TOKEN="<hs256-forged-token>"
$ curl -s http://target-app.local/api/vault/critical-secrets \
  -H "Authorization: Bearer ${TOKEN}"
# Expected: 401 Unauthorized with "invalid algorithm" message

Remediation Priority Timeline
Day	Action	Responsible Team
Day 1	Deploy fix for V-03 (Mass Assignment)	Backend Engineering
Day 1	Deploy fix for V-05 (JWT Algorithm Confusion)	Auth/Platform Engineering
Day 2	Deploy fix for V-01 (GraphQL Introspection)	Backend Engineering
Day 3	Implement network egress filtering (V-04)	Infrastructure/Security
Day 5	Deploy URL validation in report generator (V-04)	Backend Engineering
Day 7	Deploy fix for V-02 (OAuth redirect_uri)	Auth Engineering
Day 10	Address informational findings (I-01, I-02)	DevOps
Day 14	Verification retest	Security Team

Remediation recommendations are provided based on industry best practices. Implementation should be validated by the responsible engineering teams.


---

## Remediation Verification Tests

The following test cases can be used to validate that each finding has been successfully remediated. All commands assume the target is accessible and the tester holds valid credentials where required.

### V-01: GraphQL Introspection Disabled

```bash
# Confirm introspection is now blocked
curl -s http://target-app.local:8090/api/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name}}}"}'

# Expected response:
# {"errors":[{"message":"GraphQL introspection is not allowed..."}]}
```

### V-02: OAuth redirect_uri Exact Matching

```bash
# Attempt the previously successful bypass
curl -v "http://target-app.local:8090/oauth/authorize?\
client_id=app-client-production&\
redirect_uri=https://app.target-app.local/callback.attacker.com&\
response_type=code"

# Expected response:
# {"error":"invalid_request","error_description":"Invalid redirect_uri"}
# (The bypass URI must now be rejected)
```

### V-03: Mass Assignment Field Allowlisting

```bash
# Attempt to inject the role field
curl -s -X PUT http://target-app.local:8090/api/v2/users/me \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${VALID_TOKEN}" \
  -d '{"role":"admin","permissions":["admin"]}'

# Verify the role field was not applied
curl -s http://target-app.local:8090/api/v2/users/me \
  -H "Authorization: Bearer ${VALID_TOKEN}"

# Expected: User role should remain "employee", not "admin"
```

V-04: SSRF Prevention in Document Generator

```bash
# Attempt to access metadata service
curl -s -X POST http://target-app.local:8090/api/v2/reports/generate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${VALID_TOKEN}" \
  -d '{"template":"<script>fetch(\"http://169.254.169.254/latest/meta-data/\")</script>"}'

# Expected: rendering_log should show the request was blocked
# or the response should indicate URL validation failure
```

### V-05: JWT Algorithm Restriction

```bash
# Attempt to use an HS256-signed token
curl -s http://target-app.local:8090/api/vault/critical-secrets \
  -H "Authorization: Bearer ${FORGED_HS256_TOKEN}"

# Expected response:
# 401 Unauthorized — "token algorithm not permitted" or similar
# (Previously accepted HS256 tokens must now be rejected)
```

These verification tests validate that the root cause of each finding has been addressed, not merely that a workaround has been applied.
