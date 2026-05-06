
# GraphQL Endpoint Discovery & Initial Testing

**Date:** May 4, 2026  
**Time:** T+1.5h

---

## Confirmation Test

```text
$ curl -s http://target-app.local:8090/api/graphql \
  -H "Content-Type: application/json" \
  -d '{}'
```

**Response:**

```json
{
  "errors": [
    {
      "message": "Query is required"
    }
  ]
}
```

→ Confirmed: Valid GraphQL endpoint

## Introspection Test

```text
$ curl -s http://target-app.local:8090/api/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name}}}"}'
```

Response (truncated):

```json
{
  "data": {
    "__schema": {
      "types": [
        {"name": "User"},
        {"name": "VaultSecret"},
        {"name": "DebugInfo"},
        {"name": "Query"},
        {"name": "Mutation"},
        {"name": "String"},
        {"name": "ID"},
        {"name": "Boolean"},
        ...
      ]
    }
  }
}
```

**→** CRITICAL: GraphQL introspection is enabled in production

**→** Complete API schema can be enumerated
