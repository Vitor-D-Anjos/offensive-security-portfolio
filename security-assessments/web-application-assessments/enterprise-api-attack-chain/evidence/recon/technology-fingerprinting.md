
# Technology Fingerprinting

**Date:** May 4, 2026  
**Time:** T+0.5h to T+1.0h  
**Tool:** curl, manual analysis

---

## HTTP Response Headers (Port 8090)

```text
$ curl -I http://target-app.local:8090/

HTTP/1.1 404 Not Found
X-Powered-By: Express                                    ← Framework disclosure
Access-Control-Allow-Origin: *                           ← Wildcard CORS
Content-Security-Policy: default-src 'none'              ← Restrictive CSP
X-Content-Type-Options: nosniff
Content-Type: text/html; charset=utf-8
Content-Length: 140
Date: Mon, 04 May 2026 15:33:09 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```

## HTTP Response Body

```
$ curl -s http://target-app.local:8090/

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>Cannot GET /</pre>
</body>
</html>
```

## Analysis

- `X-Powered-By: Express` → Node.js application server
- 404 on root path → API-first architecture (no static index page)
- Wildcard CORS → Overly permissive cross-origin policy
- CSP: `default-src 'none'` → Blocks most XSS but allows API requests
- No authentication challenge → Anonymous access permitted

---

## Stack Inference

| Layer | Technology |
|-------|------------|
| Backend | Node.js with Express.js framework |
| API Pattern | RESTful with JSON responses |
| Authentication | Not enforced on all endpoints (confirmed later) |
| Architecture | Microservices (separate auth service on port 1337) |
