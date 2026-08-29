# Search resource and Work Graph contract

Status: **Phase 0 approval candidate**
Requirements: `SRCH-001`–`SRCH-003`, `GRAPH-001`, `GRAPH-002`, `UX-008`

Search indexes a typed envelope for Organization, Team, Project, Work Item, Document, Person, Agent, and, where the corresponding Project capability is active, Repository, Branch, Commit, code file/symbol, Pull Request, Build, Deployment, Package, Artifact, Release, Attachment, and Comment resources. Every entry carries only canonical ID/URI, resource type, container, effective label/profile version, projection version, authorized display fields, and source event checkpoint. It never becomes authoritative. Software resources are neither required nor synthesized for general Projects.

Query order is fixed: choose Organization/security-domain/container/label partitions; apply coarse authorized partitions; obtain candidate IDs; perform authoritative OpenFGA+policy-decision checks; only then form titles, snippets, suggestions, counts, facets, rollups, graph edges, and errors. Denied resources contribute nothing—including to zero/nonzero differences or timing buckets exposed to a caller.

The public `SearchResult`, result wrapper, and RFC 9457 problem shapes are closed contracts. Provider locators, hidden candidate counts, protected facets, and undeclared metadata therefore cannot be added to a conforming response.

Team/Project rollups, navigation, inbox, activity, notifications, and relationship summaries use the same filtering. Team hierarchy is an indexable relationship but never an authorization input unless an explicit policy relation separately exists.

Work Graph edges use DOM-006 direction, preserve provenance, and receive at least the join of endpoint and edge restrictions. Document live Work views execute an authorized query at render time; they do not copy task data into Markdown.

PostgreSQL is the baseline provider and OpenSearch is optional scale-out. Both pass the same corpus, leakage, replay, and parity tests. Rebuild consumes versioned events, validates checkpoint/count/hash parity privately, atomically cuts over, and can roll back to the prior projection without changing source records.
