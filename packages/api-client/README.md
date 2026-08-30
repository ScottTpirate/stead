# Stead Platform API client

This package is the only browser transport boundary. It accepts operation IDs generated
from `specs/openapi/platform-v1.yaml`, constructs same-origin `/api/v1` requests, and rejects
absolute or provider URLs. Response bodies intentionally remain `unknown`: adding a schema
code generator requires its own approved dependency and contract-owner integration.

Regenerate the checked-in operation registry without installing another dependency:

```bash
node packages/api-client/scripts/generate-operation-registry.mjs
```

The generator records the OpenAPI SHA-256 in its output. Review must fail if regeneration
changes method, path, or operation ID unexpectedly. The query store is transport-agnostic;
it deduplicates in-flight reads, supports prefetch and reversible optimistic presentation,
and aborts and clears all cached authorized state whenever principal, session, or security
domain context changes. It is never an authorization cache.
