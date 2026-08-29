# Knowledge and Commonplace contract

Documents are Markdown plus OKF-compatible frontmatter in Git. Each has stable canonical ID independent of path, exactly one Organization/Team/Project container, deterministic serialization, safe non-executable rendering, portable attachments, readable history, optimistic concurrency, and explicit draft/review/approval/supersession state.

Default Organization/Team knowledge repositories are created on first document; a Project docs repository is created with the Project. Separate repositories are mandatory where access, classification, compartments, retention, or lifecycle differs. Repository boundaries remain implementation detail in unified Knowledge navigation but are never hidden from security decisions.

Commonplace integration first uses upstream Gitea auth/Git, headless/embed, token, and navigation hooks. A temporary patch carries no Platform ontology/policy and is continuously rebased/tested. Primary iframe use is forbidden. An ADR-approved native UI fallback must preserve the same Git/OKF and upstream-compatible contracts.

Controlled content records reviewers, approval, immutable revision hash, markings, export/print obligations, and audit. Phase 1 implements deterministic editing; Yjs collaboration is required by 1.0, not Phase 0.
