
# Automated Endpoint Discovery Log

**Date:** May 4, 2026  
**Time:** T+1.0h to T+1.5h  
**Tool:** Custom bash script (`recon.sh`)

---

## Execution

```text
$ ./recon.sh

[*] Testing http://target-app.local:8090
[+] Target reachable (HTTP 404 - expected, API server)
[+] Output: recon_results_20260504_210833

Scanning 67 paths on port 8090...
This may take 2-5 minutes...
```

## Results: Accessible Endpoints

| Status | Endpoint | Details |
|--------|----------|---------|
| **400** | `/api/graphql` | Valid GraphQL endpoint — requires query in POST body |

**Response body:** `{"errors":[{"message":"Query is required"}]}`

---

## Results: 404 Responses (Confirmed Non-Existent)

| Path | Interpretation |
|------|----------------|
| `.git/HEAD` | Version control not exposed |
| `.env` | Environment config not exposed |
| `.env.backup` | No backup env files |
| `.env.production` | No production env files |
| `swagger.json` | No Swagger documentation |
| `openapi.json` | No OpenAPI spec |
| `api-docs` | No API documentation UI |
| `robots.txt` | No robots exclusion |
| `package.json` | No package manifest exposed |
| `Dockerfile` | No Docker configuration exposed |
| `docker-compose.yml` | No container orchestration files |

## Results: 403 Responses (Exists But Restricted)

None

## Results: 401 Responses (Exists But Requires Authentication)

None

## Key Findings

1. Only **one** accessible endpoint discovered: `/api/graphql`
2. The 400 response with `"Query is required"` confirms a GraphQL server
3. No sensitive files exposed through direct file access
4. API-first architecture confirmed — all endpoints under `/api/`

---

## Next Steps

1. Investigate GraphQL endpoint for introspection capabilities
2. Attempt schema enumeration
3. Test for unauthenticated queries
