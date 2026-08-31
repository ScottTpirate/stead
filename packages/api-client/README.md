# Stead Platform API client

This package is the only browser transport boundary. It accepts operation IDs and closed
request-envelope constraints generated from `specs/openapi/platform-v1.yaml`, constructs
same-origin `/api/v1` requests, and rejects absolute or provider URLs. Response bodies
intentionally remain `unknown`: adding response model generation requires its own approved
dependency and contract-owner integration.

Regenerate the checked-in operation registry without installing another dependency:

```bash
node packages/api-client/scripts/generate-operation-registry.mjs
```

The generator records the OpenAPI SHA-256 and derives method, path, parameters, mutation
headers, request-body schemas, media types, and schema-version envelopes. The runtime
rejects invalid calls before fetch and bounds response bytes and presentation-safe metadata.
The query store is transport-agnostic; it deduplicates in-flight reads, supports prefetch
and generation-ordered reversible optimistic presentation, and aborts and clears all cached
authorized state whenever principal, session, or security domain context changes. It is
never an authorization cache.
