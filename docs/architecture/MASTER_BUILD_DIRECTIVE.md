# Master Build Directive: Unified Open Work Platform

**Version:** 0.2
**Status:** Reconciled normative build specification
**Audience:** Project-manager agent, architecture agent, implementation subagents, QA/security agents
**Project name:** `Stead`
**Canonical concrete interface names:** `stead-web`, `stead-api`, `stead-worker`, `steadctl`, the Stead API, and `stead.<domain>.<action>.v<major>` event types/subjects

**Revision 0.2 reconciliation summary:** broadens the product from a developer-tool suite into an organization-wide open work and knowledge platform; makes software-delivery capabilities additive; defines hierarchical Teams without implicit permission inheritance; introduces organization/team/project knowledge containers; incorporates and preserves the approved `AGENT-001` through `AGENT-007` contracts; and replaces the single software-heavy golden path with general-work and software-extension paths. This file is the sole authoritative directive after reconciliation.

---

## 0. How the project-manager agent must use this document

This document is the authoritative build directive. The project-manager agent must decompose it into epics, issues, dependency graphs, agent assignments, acceptance tests, and release gates without changing the product philosophy or architecture.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**, and **MAY** are normative in the RFC 2119/RFC 8174 sense.

When requirements conflict, use this precedence order:

1. Prevent unauthorized disclosure, data loss, or integrity loss.
2. Preserve source-of-truth and module boundaries.
3. Preserve the unified end-user experience.
4. Preserve upgradeability and standards compatibility.
5. Preserve infrastructure portability.
6. Prefer implementation simplicity.

The project-manager agent MUST:

- Create one tracked issue for every requirement ID in this document or map multiple requirement IDs to a single issue with an explicit traceability table.
- Assign every issue an owner, dependencies, acceptance criteria, required automated tests, documentation obligations, and affected security classifications.
- Prevent multiple subagents from changing the same contract or module simultaneously unless one integration agent owns the merge.
- Require an Architecture Decision Record (ADR) before changing a locked decision.
- Reject implementation work that adds an unapproved dependency, violates the license policy, bypasses the shared authorization service, or directly accesses an upstream database.
- Maintain a machine-readable requirements-to-tests matrix.
- Treat a feature as incomplete until its tests, documentation, observability, migration behavior, authorization behavior, and rollback behavior are complete.
- Use an independent QA/security agent to validate every release candidate. The implementation agent may not be the final approver of its own work.

Subagents MUST NOT reinterpret ambiguous requirements on their own. They must either apply the defaults in this document or submit an ADR with a concrete proposal, impact analysis, and tests.

---

# 1. Product mission

Build a fully open-source, self-hostable, opinionated **open work and knowledge platform** for the whole organization.

The universal product replaces the normal Jira-and-Confluence combination for technical and nontechnical teams. For software teams, the same platform additionally replaces GitHub or equivalent source-control and software-delivery tooling.

The product must feel like **one coherent application**, not multiple applications connected by links or hidden behind a shared login.

The platform will use mature open-source engines wherever they are strong, then provide the missing integration, ontology, security, search, navigation, migration, and user experience as original platform capabilities.

The universal core is **Work + Knowledge**. Source control, pull requests, builds, packages, releases, and deployments are additive project capabilities rather than assumptions imposed on every user.

The platform MUST serve organization-wide teams including HR, finance, legal, operations, research, program management, and executive/administrative organizations. Software development is an additive capability, not an assumption of every Project.

The universal product concepts are Organization, Team, Project, Work, Work Item, Document, Person, Agent, Status, Priority, Owner, Relation, Activity, Comment, and View. In this vocabulary, Work is the product area and collection over canonical Work Items; Person is the human-facing presentation of a User principal; and a View is an authorized presentation of canonical resources rather than a separate ontology entity. Software concepts appear only where their capability is active and applicable.

The core value proposition is:

> Work, documentation, organizational knowledge, people, teams, agents, and—where applicable—code and delivery resources belong to one connected work graph, governed by one identity and authorization model, exposed through one modern interface, and stored in portable open formats on infrastructure controlled by the organization.

---

# 2. Non-negotiable product principles

## PRIN-001 — One product experience

The end user MUST interact with one product shell, one navigation model, one command palette, one search system, one inbox, one identity, and one authorization model.

The product MUST NOT expose routine users to separate Gitea, Commonplace, or Devlane branding or navigation.

Raw upstream administration interfaces MAY remain available under restricted administrative routes, but they MUST NOT be the normal workflow.

## PRIN-002 — Upstream engines remain replaceable and upgradeable

Gitea MUST remain stock upstream software.

The platform MUST NOT:

- fork Gitea;
- query or write Gitea database tables;
- import Gitea internal Go packages;
- depend on undocumented Gitea files or endpoints;
- patch Gitea templates as the primary integration mechanism.

Gitea integration MUST use documented APIs, webhooks, Git protocols, supported authentication, and supported configuration.

Commonplace MUST be integrated through upstream contributions, stable interfaces, or a thin compatibility layer. A permanent divergent Commonplace fork is prohibited. A temporary patch queue is allowed only while upstream contributions are pending and MUST be isolated, documented, tested, and kept minimal.

Devlane is the permanent frontend fork and serves as the visual foundation, interaction-pattern source, and component source. The Devlane-derived frontend MUST be converted into the platform’s primary user interface and MUST use the platform API rather than the Devlane backend as the system of record.

Devlane's ontology and routing structure are not canonical. Modules, Epics, Pages, Board, Intake, Archives, Drafts, and similar source-application concepts MUST NOT become foundational product concepts merely because the fork contains them. List, Board, Timeline, Calendar, and Triage are Views over canonical Work unless a later approved ADR establishes otherwise.

## PRIN-003 — Opinionated product semantics

The platform MUST provide a deliberately small, consistent ontology and workflow.

Administrators MUST NOT be able to create arbitrary workflow engines, dozens of custom statuses, arbitrary issue-type hierarchies, or custom objects that change the meaning of the product.

Organizations MAY rename display labels, add tags, configure notifications, configure infrastructure providers, and install approved security-label profiles. They MUST NOT redefine the canonical semantics of Project, Team, Work Item, Document, Repository, Cycle, Release, or the fixed workflow.

An organization that needs fundamentally different semantics may fork the open-source project.

## PRIN-004 — Open data and exitability

An organization MUST be able to recover its data without continuing to run this platform.

- Source code MUST remain ordinary Git repositories.
- Documents MUST remain Markdown plus Open Knowledge Format-compatible frontmatter in Git.
- Attachments MUST remain ordinary files or objects with portable manifests.
- Work data MUST be exportable as documented JSON conforming to the platform resource schemas and OSLC-inspired mappings.
- Events MUST use CloudEvents envelopes.
- Users and groups MUST be exportable in SCIM-compatible form.
- Security/compliance artifacts SHOULD be exportable in OSCAL.
- No customer data may be stored solely in an opaque proprietary binary format.

## PRIN-005 — Modular internals without microservice sprawl

The initial product MUST be a modular monolith plus replaceable upstream services and asynchronous workers, not a collection of dozens of microservices.

The baseline deployable application components are:

1. `stead-web`
2. `stead-api`
3. `stead-worker`
4. `steadctl`
5. stock Gitea
6. PostgreSQL
7. NATS with JetStream
8. OpenFGA
9. a separate deterministic classification/context/information-flow policy layer

Optional scale or enterprise components include OpenSearch, Valkey, an external object store, and an external identity provider.

Internal modules MUST have stable contracts, owned database schemas/tables, emitted domain events, and isolated tests. One module MUST NOT write another module’s tables directly.

## PRIN-006 — Standards first, not standards theater

Where an applicable mature open standard exists, the platform MUST use it or publish an explicit profile/mapping to it.

The product MUST NOT adopt RDF, SPARQL, XACML, or another complex implementation merely to claim standards compliance when a simpler interoperable representation meets the requirement.

Standards mappings must preserve portability while allowing a practical PostgreSQL/JSON/Git implementation.

## PRIN-007 — Secure by default

Authorization is deny-by-default. Authentication, relationship authorization, classification/handling policy, and request context MUST be evaluated for every protected operation.

No administrator role automatically bypasses classification, compartment, handling, or need-to-know restrictions.

The product MUST distinguish “security-ready” from “certified” or “compliant.” It MUST NOT claim FedRAMP authorization, FIPS validation, CMMC compliance, classified-system approval, or cross-domain certification merely because supporting controls exist.

## PRIN-008 — Infrastructure agnostic

No public cloud is part of the core architecture.

The same release MUST support:

- a single local machine;
- Docker-compatible container runtimes;
- Kubernetes distributions including local, bare-metal, and managed cloud Kubernetes;
- AWS, Azure, GCP, and S3-compatible or equivalent services;
- connected and air-gapped deployments.

Cloud-specific services MAY be supported through adapters but MUST NOT be required.

## PRIN-009 — Simple installation and operation

The normal installation path MUST be guided and short.

Users MUST NOT be required to manually compose a large configuration file, follow a ten-page sequence, or understand every internal service.

Advanced customization MAY have detailed documentation, but the supported installation profiles MUST be executable by `steadctl` with validated defaults.

## PRIN-010 — Testing is part of the architecture

Every architecture boundary, fixed workflow, provider contract, authorization rule, classification rule, event schema, migration, installation profile, and upgrade path MUST be automatically testable.

No requirement is complete without its tests.

## PRIN-011 — Essential security is never a proprietary edition feature

The open-source distribution MUST include all essential identity, authorization, classification, audit, backup, encryption integration, and deployment capabilities.

The project MUST NOT create an “open core” model that reserves necessary enterprise or government security for a closed edition.

## PRIN-012 — No built-in cross-domain solution

A deployment operates inside an approved security domain with a configured maximum sensitivity/classification.

The platform MUST NOT move information between unclassified and classified networks, between classification levels, or between accredited security domains by itself.

Cross-domain transfer requires an externally approved cross-domain solution and is outside core product scope.

## PRIN-013 — Universal core, additive capabilities

Every Project MUST provide the universal experience of:

- Overview;
- Work;
- Docs.

Software-delivery capabilities MAY be activated through system-defined capability bundles. Users MUST NOT see empty or irrelevant Code, Pull Request, Build, Package, Release, or Deployment areas when those capabilities are not active or authorized.

Gitea remains the required initial backing engine for tracker issues and Git-backed documents even when a Project has no source-code repository. The existence of Gitea underneath the platform MUST NOT force developer terminology or developer navigation onto nontechnical users.

## PRIN-014 — Progressive disclosure and one mental model

The default interface MUST expose the smallest useful set of concepts and actions. Advanced power MUST be discoverable through command search, contextual actions, keyboard shortcuts, and progressive disclosure rather than permanently visible controls.

The product MUST NOT become simpler for one team by becoming a differently structured product for another team. Capability visibility may vary according to project configuration and authorization, but canonical terminology, object behavior, navigation order, and interaction rules remain system-owned.

## PRIN-015 — Organizational hierarchy is not authorization inheritance

Teams MAY be hierarchical for navigation, accountability, reporting, ownership, and policy targeting.

A Team's parent/child position MUST NOT by itself grant access to child or parent Team resources. Permission grants require explicit OpenFGA relationships or approved policy. Restrictive governance defaults and explicit denies MAY cascade downward where specified by policy, but hierarchy MUST NOT create an implicit access grant.

---

# 3. Scope and explicit non-goals

## 3.1 Required product scope

### Universal organization-wide scope

The production target includes:

- organizations and hierarchical Teams;
- Projects, cycles, initiatives, and roadmaps;
- issue/work-item management for technical and nontechnical teams;
- organization-, Team-, and Project-scoped Git-backed documentation;
- document review, approval, provenance, and history;
- live relationships and views connecting Docs and Work;
- unified global search and knowledge browsing;
- unified inbox and notification routing;
- unified activity and audit;
- identity provisioning and single sign-on;
- relationship-based and attribute/classification-based authorization;
- classification-aware handling for regulated, high-assurance, classified, and specialized deployments;
- migration from Jira and Confluence;
- local, Kubernetes, cloud, and air-gapped installation;
- backups, restores, upgrades, diagnostics, and observability;
- open APIs, events, export formats, and provider contracts.

### Additive software-delivery scope

When the relevant system-defined capabilities are active, the same product includes:

- Git hosting and repository management;
- pull requests and code review;
- branch protection and repository governance;
- CI/CD orchestration through Gitea Actions;
- package, artifact, release, and deployment visibility;
- migration from GitHub or another supported SCM provider.

## 3.2 Non-goals

The project MUST NOT attempt to provide:

- arbitrary Jira-style workflow builders;
- arbitrary user-defined database objects;
- arbitrary Confluence-style executable macros;
- per-customer changes to the canonical ontology;
- full emulation of every GitHub, Jira, or Confluence API in the first release;
- a built-in chat platform;
- a built-in general-purpose office suite;
- a built-in cross-domain solution;
- per-file or per-page secrecy inside a Git repository that users can clone;
- a required SaaS control plane, license server, or outbound telemetry endpoint;
- a fork of Gitea;
- a permanent fork of Commonplace;
- unbounded third-party in-process plugins.

---

# 4. Required technology and repository structure

## ARCH-001 — Required implementation languages

- The primary frontend MUST use React and TypeScript, derived from Devlane’s web application and design language.
- The platform API, background worker, provider adapters, and CLI MUST use Go unless an ADR demonstrates a compelling technical reason otherwise.
- Relationship and need-to-know authorization MUST use OpenFGA models.
- Classification, contextual/attribute, handling, information-flow, infrastructure, and explicit-deny rules MUST use the versioned deterministic policy-decision contract. The implementation is selected by ADR; OPA/Rego is permitted but is not required.
- Persistent relational data MUST use PostgreSQL.
- Event transport MUST use NATS JetStream.
- Document editing MUST use a Markdown-capable TipTap-based editor. Real-time collaborative editing SHOULD use Yjs.
- Public schemas MUST use JSON Schema 2020-12.

## ARCH-002 — Required monorepo layout

The initial repository MUST use this logical layout. Names may be adjusted only through an ADR, but boundaries must remain.

```text
/apps
  /web                    # Devlane-derived unified frontend; deploys as stead-web
  /core                   # Go platform API/BFF and modular domain core; deploys as stead-api
  /worker                 # Go asynchronous consumers/reconcilers/indexers; deploys as stead-worker
  /steadctl               # installer, upgrade, backup, restore, doctor CLI

/modules
  /organization
  /identity
  /authorization
  /classification
  /project
  /work
  /knowledge
  /scm
  /ci
  /artifact
  /search
  /notification
  /audit
  /agent                  # registry/run contracts; execution added only in its approved phase
  /migration

/providers
  /gitea
  /commonplace
  /blob-filesystem
  /blob-s3
  /blob-azure
  /blob-gcs
  /search-postgres
  /search-opensearch
  /identity-oidc
  /identity-scim
  /agent-a2a              # external agent-runtime interoperability
  /notifications-email
  /notifications-webhook

/packages
  /domain-schemas
  /provider-sdk
  /event-schemas
  /design-system
  /api-client
  /test-fixtures

/policies
  /openfga
  /policy-decision        # implementation-neutral deterministic policy contract
  /security-label-profiles
  /deployment-domains     # profile-qualified ceilings and environment assurance policy

/specs
  /openapi
  /asyncapi
  /work-graph-profile
  /okf-profile
  /oscal
  /mcp
  /a2a

/deploy
  /compose
  /helm
  /airgap
  /examples

/tests
  /contract
  /integration
  /e2e
  /security
  /performance
  /upgrade
  /backup-restore
  /classification

/docs
  /architecture
  /adr
  /operator
  /user
  /contributor
```

## ARCH-003 — Runtime boundaries

`stead-web` MUST call only the versioned platform API. It MUST NOT call Gitea, Commonplace, OpenFGA, the policy-decision layer, NATS, or storage providers directly from the browser.

`stead-api` MUST:

- expose the public/BFF API;
- enforce authentication and authorization;
- own synchronous domain operations;
- maintain the transactional outbox;
- call provider interfaces rather than provider-specific code;
- return canonical platform resources to the UI.

`stead-worker` MUST:

- publish outbox events to NATS;
- consume Gitea/Commonplace/provider events;
- reconcile upstream state;
- update search projections;
- create notifications;
- write audit projections;
- perform migrations and imports;
- execute retryable asynchronous work.

`steadctl` MUST:

- install;
- validate;
- diagnose;
- upgrade;
- back up;
- restore;
- export;
- import;
- create air-gap bundles;
- render effective configuration.

## ARCH-004 — Database ownership

- Gitea MUST use its own database or database/schema boundary.
- OpenFGA MUST use its supported datastore in a separate database/schema.
- Platform modules MUST own their tables and migrations.
- Search indexes, activity feeds, and analytics are rebuildable projections, not systems of record.
- NATS is transport and replay storage, not the authoritative business database.
- No service may rely on querying another product’s internal tables.

## ARCH-005 — API and schema versioning

- Every public HTTP API MUST be documented in OpenAPI 3.1.1.
- Every event channel and message MUST be documented in AsyncAPI 3.1.x.
- Every JSON payload MUST have a JSON Schema 2020-12 definition.
- Public IDs MUST use UUIDv7. Human-readable keys such as `IAM-123` are separate display identifiers.
- API errors MUST use RFC 9457 Problem Details.
- Mutable resources MUST support optimistic concurrency using versions and HTTP conditional requests/ETags.
- Breaking API and event changes require a new major version and a migration period.

---

# 5. Standards requirements

## STD-001 — Standards matrix

The implementation MUST follow this matrix.

| Concern | Required standard or profile | Required use |
|---|---|---|
| Requirement language | RFC 2119 / RFC 8174 | Normative project specifications |
| HTTP APIs | OpenAPI 3.1.1 | All public and provider HTTP contracts |
| Schemas | JSON Schema 2020-12 | Domain objects, events, config, exports |
| API errors | RFC 9457 | All structured HTTP errors |
| IDs | RFC 9562 UUIDv7 | Canonical internal resource IDs |
| Events | CloudEvents 1.0 | Every domain/integration event envelope |
| Async contracts | AsyncAPI 3.1.x | NATS subjects, payloads, producers, consumers |
| Work/lifecycle semantics | OSLC Core 3.0 and Change Management 3.0 concepts | Canonical work-resource profile and external mapping |
| Knowledge | Open Knowledge Format 0.2-compatible Markdown/frontmatter | Git-backed docs |
| Provenance | W3C PROV concepts | Derivation, attribution, generation, source lineage |
| Human activity | ActivityStreams 2.0 concepts | Unified activity feed semantics |
| Agent tools and context | Model Context Protocol (MCP), pinned supported profile | Permission-aware agent access to platform tools and data |
| Agent interoperability | Agent2Agent Protocol (A2A), pinned supported profile | External agent registration, dispatch, task progress, and artifacts |
| Authentication | OpenID Connect | Human SSO |
| Provisioning | SCIM 2.0, RFC 7643/7644 | Users and groups |
| Authorization model | OpenFGA plus NIST SP 800-162 ABAC principles | Relationships and attributes |
| Policy as code | Versioned deterministic policy-decision contract; implementation selected by ADR | Classification, handling, context, information-flow, infrastructure, and explicit-deny policy |
| Security controls | NIST SP 800-53 Rev. 5.x; NIST SP 800-171 Rev. 3 where CUI applies | Control mapping and secure profiles |
| Security automation | NIST OSCAL | Component definition and control mappings |
| Zero trust | NIST SP 800-207/207A principles | No implicit network trust |
| Security categorization | FIPS 199 concepts | Deployment impact categorization |
| Containers | OCI Image and Distribution Specifications | Images and artifact distribution |
| Deployment | Kubernetes and Helm | Portable production deployment |
| Observability | OpenTelemetry/OTLP | Traces, metrics, logs, context |
| SBOM | SPDX 3.0 | Release SBOMs and license expressions |
| Build provenance | SLSA provenance | Release and CI artifact provenance |
| Artifact signing | Sigstore/Cosign-compatible signatures | Images, charts, release artifacts |
| Accessibility | WCAG 2.2 AA | Primary UI |
| Compliance artifacts | OSCAL JSON/YAML | Machine-readable security evidence |

## STD-002 — Platform resource profile

The architecture agent MUST publish a versioned **Open Work Graph Profile** (`OWGP`) before implementation of domain modules.

OWGP MUST:

- use simple canonical JSON resources;
- map relevant fields and relationships to OSLC concepts;
- use stable canonical URIs;
- use W3C PROV concepts for source, derivation, generation, and attribution;
- allow JSON-LD representation as an optional serialization;
- avoid requiring an RDF database or SPARQL;
- define validation through JSON Schema;
- define relationship types and cardinalities;
- define compatibility and deprecation rules;
- define an export/import conformance suite.

---

# 6. Canonical domain model

## DOM-001 — Common resource envelope

Every canonical resource MUST include:

```json
{
  "id": "uuidv7",
  "uri": "canonical-provider-independent-uri",
  "kind": "resource-kind",
  "schema_version": "1.0",
  "version": 1,
  "organization_id": "uuidv7",
  "container": {
    "kind": "organization|team|project",
    "id": "uuidv7",
    "uri": "canonical-container-uri"
  },
  "project_id": "uuidv7-or-null",
  "title": "human title",
  "created_at": "RFC3339 timestamp",
  "created_by": "principal URI",
  "updated_at": "RFC3339 timestamp",
  "updated_by": "principal URI",
  "security_label_id": "uuidv7",
  "provenance": {},
  "external_references": [],
  "relationships": []
}
```

Resource-specific fields are added through versioned schemas.

`container` identifies the resource's primary organization, Team, or Project knowledge/work boundary. `project_id` is present only for Project-scoped resources and MUST agree with the Project container or canonical Project relationship.

## DOM-002 — Canonical entities

The core ontology is fixed to:

- Instance
- Organization
- User
- Directory Group
- Agent
- Agent Run
- Service Principal
- Team
- Initiative
- Project
- Cycle
- Work Item
- Document
- Repository
- Branch
- Commit
- Pull Request
- Build
- Deployment
- Release
- Package
- Artifact
- Attachment
- Comment
- Activity
- Notification
- Audit Record
- Security Label

No other first-class entity may be added without an ADR and ontology review.

## DOM-003 — Canonical hierarchy

```text
Instance
└── Organization
    ├── Directory Groups
    ├── Organization Knowledge
    ├── Teams
    │   ├── Child Teams
    │   ├── Team Knowledge
    │   └── Owned/Contributing Projects
    ├── Initiatives
    └── Projects
        ├── Work Items
        ├── Project Documents
        ├── Repositories, when enabled
        ├── Cycles/Milestones
        ├── Builds, when enabled
        ├── Releases, when enabled
        └── Artifacts, when enabled
```

A Project may have zero, one, or many code repositories and one or many documentation repositories/security containers.

A Project is never equivalent to a repository.

A Document MUST belong to exactly one Organization, Team, or Project container. A Work Item MUST remain Project-scoped.

## DOM-004 — Work-item model

Allowed canonical work-item types are:

- `deliverable` — a result or larger unit of value;
- `task` — an actionable unit of work;
- `problem` — something incorrect, degraded, blocked, or requiring correction.

The `software` preset MAY display `deliverable` as **Feature** and `problem` as **Bug**. Other presets SHOULD use the universal labels. Display labels MUST NOT change canonical semantics or API values.

Allowed statuses are:

- `backlog`
- `todo`
- `in_progress`
- `blocked`
- `done`
- `canceled`

Allowed priorities are:

- `none`
- `low`
- `medium`
- `high`
- `urgent`

A Work Item:

- MUST belong to exactly one Project;
- MAY have one parent;
- MUST NOT exceed three levels of work-item nesting;
- MAY relate to other work items through `blocks`, `blocked_by`, `duplicates`, `duplicated_by`, and `relates_to`;
- MAY belong to one Cycle;
- MAY be associated with one Initiative through its Project or an explicit relationship;
- MAY have an estimate from the fixed set `1, 2, 3, 5, 8`;
- MUST have a stable human key of the form `<PROJECTKEY>-<NUMBER>`.

Arbitrary user-defined work-item types, statuses, priority scales, and user-facing custom fields are prohibited.

Provider/import-specific values MAY be retained in namespaced `source_metadata`, but they MUST NOT alter canonical behavior.

## DOM-005 — Document model

Allowed canonical document types are:

- `page`;
- `specification`;
- `decision`;
- `procedure`;
- `policy`.

The `software` preset MAY display `decision` as **Architecture Decision** and `procedure` as **Runbook**. Display labels MUST NOT change canonical semantics or serialized values.

Allowed document states are:

- `draft`
- `in_review`
- `approved`
- `superseded`
- `archived`

Documents MUST:

- be stored as Markdown in Git;
- contain OKF-compatible YAML frontmatter;
- contain a stable platform document ID independent of path;
- expose typed relationships to Projects, Work Items, Repositories, Pull Requests, Releases, and other Documents;
- preserve readable Git history;
- reject executable MDX, arbitrary scripts, and unsafe embedded HTML by default;
- use attachment links that remain portable through export manifests.

## DOM-006 — Relationship model

The initial typed relationships are:

```text
Team parent_of Team
Team owns Project
Team contributes_to Project
Team maintains Repository
Directory Group supplies_membership_to Team
Project contains Work Item
Project contains Document
Project links Repository
Initiative contains Project
Document specifies Work Item
Document supersedes Document
Document references Repository
Work Item implemented_by Pull Request
Work Item blocks Work Item
Pull Request changes Repository
Pull Request addresses Work Item
Commit generated Build
Build produces Artifact
Release contains Artifact
Deployment deploys Release
Resource derived_from Resource
Resource attributed_to Principal
Agent assigned_to Work Item
Agent Run executes Work Item
Agent Run produces Resource
```

Relationship names and direction are canonical and versioned. UI display text may vary, but semantics may not.

## DOM-007 — Provenance and classification propagation

Any resource generated or derived from another resource MUST record provenance sufficient to identify its source.

Effective security labels MUST be computed using a defined join operation over:

- the container/default label;
- explicitly assigned label;
- labels of source/derived-from resources;
- applicable handling rules.

A derived resource MUST NOT silently receive a less restrictive effective label than any source that contributed protected content.

## DOM-008 — Project capability model

Project capabilities are system-defined and versioned. Administrators MUST NOT create arbitrary capability types or arbitrary primary tabs.

Required universal capability set:

- `work`;
- `docs`.

Initial optional capability set:

- `scm`;
- `code_review`;
- `ci`;
- `packages`;
- `releases`;
- `deployments`.

Capability dependencies are fixed:

- `code_review` requires `scm`;
- `ci` requires `scm`;
- `packages`, `releases`, and `deployments` may require `scm` or another approved artifact provider according to their provider contract.

The initial Project creation presets are:

- `general`: Work + Docs;
- `software`: Work + Docs + SCM + Code Review + CI + Packages + Releases;
- `controlled_knowledge`: Work + Docs with controlled-document review defaults.

Presets activate capabilities and seed approved views/documents. They MUST NOT change canonical Work Item types, statuses, relationship semantics, authorization behavior, or navigation order.

Capability activation and deactivation MUST be authorized, audited, reversible where technically possible, and MUST preserve existing data. The UI MUST derive visible areas from active capabilities plus authorization.

## DOM-009 — Team hierarchy and accountability

A Team:

- MUST belong to exactly one Organization;
- MAY have zero or one parent Team in the same Organization;
- MUST form a cycle-free hierarchy;
- MUST NOT exceed twelve hierarchy levels;
- MAY contain users, agents, and service accounts through explicit membership relationships;
- MAY be bound to one or more external Directory Groups for synchronized membership;
- MAY own many Projects and contribute to many Projects;
- MUST retain its stable canonical ID and URI when renamed or reparented.

Every Project MUST have exactly one owning Team and MAY have zero or more contributing Teams. Ownership establishes accountability and default policy targeting, not implicit access for every ancestor Team.

Reparenting, directory binding, ownership changes, and membership-source changes MUST be audited.

## DOM-010 — Principal and assignment model

A canonical `PrincipalRef` is a tagged union of:

- `user`;
- `agent`;
- `service_account`;
- `directory_group`.

The `service_account` discriminator references the canonical Service Principal entity. A Directory Group is a membership and authorization subject but is not an acting principal. An acting principal MUST be a `user`, `agent`, or `service_account`.

Code, schemas, events, audit records, comments, assignments, review requests, and ownership metadata MUST NOT assume the acting principal is human.

A Work Item MAY be assigned to a User or Agent principal. A Project or Work Item MAY separately identify a responsible Team. Provider-specific limitations, including Gitea user-only assignees, MUST remain inside the provider adapter and MUST NOT redefine the canonical model.

Agent execution remains external to the core platform. The platform owns Agent identity, registration, authorization, assignment, Agent Run state, audit, and interoperability contracts; it does not own model reasoning, prompts, or agent-framework internals.

## DOM-011 — Project model and lifecycle

A Project MUST include:

- exactly one owning Team;
- zero or more contributing Teams;
- one system-defined preset;
- a set of active system-defined capabilities;
- a stable human key;
- a title and concise purpose;
- one lifecycle state;
- optional start and target dates;
- an effective security label/container policy;
- archival metadata separate from lifecycle state.

Allowed Project lifecycle states are:

- `planned`;
- `active`;
- `paused`;
- `completed`;
- `canceled`.

Archival is a reversible visibility/retention operation represented by `archived_at` and `archived_by`, not an additional workflow state. Completed or canceled Projects remain searchable and linkable unless retention policy requires otherwise.

A Project preset MAY seed a purpose-appropriate overview, views, and documents, but MUST NOT create a new ontology or workflow.

---

# 7. Gitea and source-control requirements

## SCM-001 — Stock Gitea integration

Gitea is the required initial SCM, issue, project-board, action, package, and release engine.

The platform MUST integrate through:

- REST APIs;
- webhooks with HMAC validation;
- Git over SSH and HTTPS;
- OAuth/OIDC or supported external authentication;
- documented admin and repository configuration.

The Gitea adapter MUST expose capability-specific interfaces rather than one unbounded provider interface.

Required provider capabilities include:

- RepositoryProvider
- GitProvider
- PullRequestProvider
- IssueProvider
- ProjectBoardProvider
- MilestoneProvider
- ActionsProvider
- PackageProvider
- ReleaseProvider
- OrganizationProvider
- PermissionSyncProvider
- WebhookProvider

## SCM-002 — Project tracker repository

Every Platform Project MUST have exactly one dedicated Gitea tracker repository created and managed by the platform.

The tracker repository:

- stores the Project’s Gitea Issues;
- stores the fixed Gitea Project board used for canonical workflow columns;
- stores managed labels and milestones;
- MAY contain a minimal README but is not a code repository;
- is hidden from normal code navigation;
- is visible only through restricted raw-provider/admin views;
- provides the issue number used in the canonical human work key.

## SCM-003 — Canonical mapping to Gitea

The mapping is fixed:

| Platform concept | Gitea storage |
|---|---|
| Work Item title/body | Issue title/body |
| Work Item comments/reactions | Issue comments/reactions |
| Work Item assignees | Issue assignees |
| Work Item type | Managed `type/*` label |
| Work Item priority | Managed `priority/*` label |
| Work Item status | Fixed Project-board column |
| Done/canceled closure | Gitea closed state plus managed status |
| Cycle/release target | Platform Cycle mapped to Gitea milestone |
| Parent/child | Platform database relationship |
| Cross-project dependency | Platform work graph |
| Estimate | Platform metadata |
| Initiative | Platform work graph |
| Canonical activity | Event/activity projection |

The platform MUST reconcile this mapping through webhooks plus scheduled full reconciliation.

## SCM-004 — Direct-provider changes

Changes made directly in Gitea MUST either:

- be accepted and reconciled when they fit the canonical model; or
- be rejected/reset with a clear audit event when they would violate the canonical model.

The raw Gitea UI MUST be considered an administrative/escape interface, not the primary product.

## SCM-005 — Compatibility and upgrades

The project MUST maintain automated contract tests against:

- the current pinned Gitea version;
- the previous two supported minor versions;
- the next release candidate or nightly build when available.

A Gitea version may be declared supported only after the full provider contract and golden end-to-end suite pass.

Gitea images MUST be pinned by version and digest.

`steadctl upgrade` MUST run compatibility preflight checks before changing Gitea.

## SCM-006 — Branch and repository policy

The platform MUST provide an open-source replacement for organization-wide repository policy even when Gitea Community lacks inheritance.

Platform policy MUST be able to enforce and reconcile:

- protected branches;
- required reviews;
- required status checks;
- signed-commit/tag policy where configured;
- deletion/force-push restrictions;
- CODEOWNERS-equivalent review rules;
- repository visibility;
- runner pool assignment;
- security label and security domain;
- archival and retention.

Policy is declared once at Organization, Team, or Project scope and reconciled to Gitea repositories.

---

# 8. Knowledge and Commonplace requirements

## DOC-001 — Git is the documentation system of record

Documents MUST be stored in dedicated Gitea Git repositories by default.

Each Organization and Team SHOULD have a default knowledge repository when its first document is created. A Project’s default docs repository SHOULD be created automatically with the Project. Additional docs repositories MAY be linked when permission, classification, retention, or lifecycle boundaries require them.

The unified Knowledge experience MUST browse authorized Organization, Team, and Project documents without exposing repository boundaries as the primary information architecture.

Documents MAY live beside code when a project explicitly chooses repository-local documentation, but the platform UI MUST present both models consistently.

## DOC-002 — Commonplace compatibility without permanent fork

The docs workstream MUST first implement and propose upstream:

1. a Gitea Git/authentication provider for Commonplace;
2. an embeddable/headless integration contract;
3. design-token and navigation hooks needed for the shared shell.

The platform MUST NOT use an iframe for the primary docs experience.

Until upstream support is released, the project MAY carry a minimal isolated patch series. The patch series MUST:

- contain no platform ontology;
- contain no platform authorization logic;
- be automatically rebased and tested against Commonplace upstream;
- be removable after upstream adoption.

If an embeddable Commonplace integration cannot satisfy the unified UX by the Beta milestone, the platform MUST implement a native docs UI against the same Git/OKF contracts while preserving Commonplace compatibility and contributing reusable components upstream. This fallback requires an ADR but does not permit a permanent divergent data model.

## DOC-003 — Editing and collaboration

The editor MUST:

- provide a high-quality nontechnical rich-text experience;
- serialize deterministically to Markdown;
- support code blocks, tables, callouts, images, links, diagrams through safe formats, and drag/drop attachments;
- preserve valid manual Markdown edits;
- use optimistic concurrency and show intelligible conflicts;
- support drafts and publication;
- support review-required documents through branches and pull requests;
- support real-time collaboration with Yjs before the 1.0 production release;
- never lose edits during reconnects or concurrent updates.

## DOC-004 — Document security boundary

A cloneable Git repository is a security and classification boundary.

All documents in a docs repository MUST be accessible to every principal with clone/read permission to that repository.

The platform MUST NOT claim page-level secrecy inside a repository that users can clone.

If documents need different access, classification, compartment, releasability, or retention, they MUST be stored in separate repositories/security containers. The unified UI may present them together only after authorization.

## DOC-005 — Document review and controlled content

Documents marked as `policy`, `decision`, or otherwise configured as controlled content MUST support:

- designated reviewers;
- approval records;
- immutable approved revision hash;
- supersession relationships;
- classification/handling marking;
- export/print markings;
- audit history.

---

# 9. Unified frontend and user experience requirements

## UX-001 — Single application shell

The Devlane-derived frontend MUST be the sole primary application shell.

Required universal primary navigation, in this order:

- Home;
- Inbox;
- My Work;
- Projects;
- Knowledge;
- Teams.

Search MUST be persistently accessible through the global command/search control and keyboard shortcut rather than requiring a dedicated navigation destination.

Administration MUST live in an authorized organization/account surface rather than permanent primary navigation for ordinary users.

An optional global Code destination MAY appear only when the current principal has access to at least one SCM resource. It MUST be system-derived, not manually rearranged by administrators.

A Project page MUST provide no more than these primary areas:

- Overview;
- Work;
- Docs;
- Code, when `scm` is active and authorized;
- Delivery, when one or more of `ci`, `packages`, `releases`, or `deployments` is active and authorized.

Pull Requests and repository details are subviews of Code. Builds, packages, releases, artifacts, and deployments are subviews of Delivery. Activity is integrated into Overview and resource timelines. Settings are contextual and MUST NOT occupy a normal primary Project tab.

A Team page MUST provide a simple view of its people, hierarchy, Projects, aggregate Work, and Team Knowledge without inventing separate Team-specific versions of those objects.

Navigating among these views MUST NOT feel like changing applications.

## UX-002 — Shared interaction vocabulary

The same reusable components and interaction rules MUST be used for:

- comments;
- mentions;
- watchers/subscriptions;
- activity;
- history;
- permissions;
- security markings;
- relationships;
- attachment handling;
- keyboard shortcuts;
- creation dialogs;
- filtering and saved views.

Required global interactions:

- command palette for navigation and creation;
- global search shortcut;
- `@` user/team mentions;
- canonical work-item references;
- canonical repository/PR references;
- deep links that remain stable after provider migration.

## UX-003 — Classification and handling display

The UI MUST display the effective security label wherever protected content is shown.

Security badges, banners, document/export markings, warnings, and accessible presentation MUST be driven by the active validated security-label profile or by a versioned system renderer declared for that profile. Profile IDs and profile-specific vocabulary MUST NOT trigger privileged authorization behavior or require a fork of `stead-web`. Text and markings are authoritative; color is supplemental and MUST NOT be the only signal.

Where an active profile or deployment security-domain policy requires them, the UI MUST support:

- persistent top and bottom classification/handling banners;
- document and export markings;
- visible session/security-domain indicator;
- warnings before export, copy, or share operations where policy requires;
- no hidden “admin bypass” view.

The frontend MUST never decide authorization locally. UI hiding is supplemental only; the server decision is authoritative.

## UX-004 — Accessibility and performance

The primary interface MUST meet WCAG 2.2 AA.

Keyboard navigation MUST be first-class.

Critical pages MUST render useful content before optional analytics or secondary panels.

The frontend MUST not block on unrelated provider calls; the BFF must aggregate or progressively return authorized data.

## UX-005 — No configuration-induced UX fragmentation

Organizations MAY configure branding, display names, integrations, and infrastructure.

They MUST NOT be able to rearrange core navigation, replace the canonical workflow with arbitrary states, or add arbitrary mandatory fields that make different teams experience different products.

## UX-006 — Capability-driven progressive disclosure

The UI MUST render only capabilities that are active and authorized. It MUST NOT show disabled developer tabs, empty module placeholders, or configuration switches that ordinary users cannot act on.

The same canonical route and component families MUST support both a general Project and a software Project. Capability variation MUST NOT create separate frontend applications or divergent design systems.

Project creation MUST begin with the three system-defined presets from DOM-008 and a short description of the experience each enables. Advanced provider configuration occurs after creation and only for authorized users.

## UX-007 — Universal object surfaces and context preservation

Every major canonical resource MUST support a consistent object surface with:

- canonical title and type;
- owner/responsible Team or principal;
- status where applicable;
- effective security label;
- typed relationships;
- comments/activity/history where applicable;
- watch/subscription state;
- stable deep link.

Work Items, Documents, Pull Requests, Builds, Releases, People, Teams, and Agents SHOULD be openable in a shared context-preserving peek/sheet as well as a full page. Opening a related object MUST NOT unnecessarily destroy the user's current navigation or filter context.

Nested modal stacks are prohibited. The interface MUST NOT present more than one blocking modal layer at a time.

## UX-008 — Work and Knowledge are visibly connected

Documents MUST support authorized live Work views rather than copied task tables. A live Work view is a rendered query over canonical Work Items and MUST preserve authorization, filtering, classification, and deep links.

The editor SHOULD support converting selected document text into a Work Item, creating a Document from a Work Item, and inserting typed references to Work Items, Documents, Teams, People, Agents, Repositories, Pull Requests, Builds, and Releases.

Every Work Item and Document SHOULD show a compact contextual relationship strip for its most important connected resources. The product MUST favor these typed connections over manually maintained duplicate links.

## UX-009 — Simplicity and visual design constitution

The frontend workstream MUST publish and test a design constitution with these rules:

1. one primary action per screen or state;
2. progressive disclosure before permanent controls;
3. recognition over recall through stable terminology, icons, and placement;
4. direct manipulation and inline editing where safe;
5. visible save, sync, agent, build, and authorization state;
6. reversible actions, history, and safe undo where feasible;
7. no vanity dashboard elements that do not support a decision or action;
8. no administrator-controlled navigation rearrangement;
9. no duplicate settings for the same behavior;
10. no empty capability areas;
11. keyboard and screen-reader parity with pointer interaction;
12. classification and handling markings integrated as calm, unmistakable product chrome rather than optional decoration.

The design MAY be inspired by Linear, Devlane, Commonplace, and high-quality native applications, but MUST NOT copy another product's information architecture when it conflicts with the platform ontology.

---

# 10. Identity, authorization, and classification requirements

## AUTH-001 — Authentication and provisioning

Human authentication MUST use OpenID Connect.

User and group provisioning MUST support SCIM 2.0.

Development/local mode MAY provide a bootstrap local administrator, but production profiles MUST require OIDC or an approved external authentication gateway.

PIV/CAC or smart-card authentication MUST be integrated through an external identity provider or approved gateway; the platform MUST NOT implement card validation itself.

Service-to-service authentication MUST use short-lived credentials and SHOULD support mTLS or workload identity.

## AUTH-002 — Combined authorization architecture

The platform MUST use a central authorization service that combines:

1. **OpenFGA** for relationship and need-to-know decisions;
2. a separate **deterministic classification/context/information-flow policy layer** for attribute-based, classification, handling, contextual, infrastructure, and explicit-deny rules;
3. provider-level enforcement for direct Git, package, artifact, and runner access.

An access decision is allowed only when all required checks allow it and no deny rule applies.

The authorization decision flow is:

```text
Authenticate principal
→ Resolve trusted principal attributes and session context
→ Resolve canonical resource and effective security label
→ OpenFGA relationship/permission check
→ Deterministic classification, handling, context, information-flow, and explicit-deny evaluation
→ Provider/path-specific enforcement check
→ Audit the decision metadata
→ Allow or deny
```

No module may implement its own alternative authorization logic.

## AUTH-003 — OpenFGA responsibilities

OpenFGA MUST model:

- organization membership;
- team membership;
- project ownership and participation;
- repository reader/writer/maintainer;
- document reader/editor/reviewer;
- work-item viewer/editor/assignee;
- release approver;
- security officer/classification manager;
- delegated service-principal access;
- explicit inherited relationships from Team and Project where defined by the authorization model;
- Agent assignment and task-scoped delegation;
- Directory Group to Team membership bindings.

The Team parent/child relationship MUST NOT automatically imply viewer, editor, owner, or administrator access. Any authorized inheritance must be explicit in the OpenFGA model and covered by model tests.

All OpenFGA models MUST have model tests and migration tests before deployment.

## AUTH-004 — Deterministic policy-decision layer responsibilities

The policy-decision layer MUST evaluate:

- sensitivity/classification dominance;
- compartments/program access;
- dissemination and releasability controls;
- CUI handling regimes/categories;
- citizenship/organization restrictions where configured;
- authentication strength;
- device trust;
- network/security zone;
- session security ceiling;
- time and authorization expiry;
- export/download/share restrictions;
- data-flow and downgrade rules;
- explicit organization policy denies;
- CI runner, artifact, and deployment policy;
- infrastructure admission policy where enabled.

Its policy bundles and decisions MUST be deterministic, versioned, signed, tested, portable, and auditable. The contract is implementation-neutral. OPA/Rego MAY be selected through an approved ADR, but no OPA service, Rego representation, or OPA-specific API is required by this directive.

## AUTH-005 — Trusted attributes

Clearance, compartments, citizenship/releasability, training, employment status, and similar attributes MUST come from configured trusted attribute authorities.

Users MUST NOT self-assert or edit these attributes.

Each trusted attribute MUST include:

- source/authority;
- issue time;
- expiration or review time;
- version;
- provenance;
- sensitivity;
- last synchronization result.

Expired or unverifiable attributes MUST fail closed.

## AUTH-006 — Agent, service, and group principals

Authentication and authorization contracts MUST distinguish:

- acting principal;
- principal type;
- initiating/delegating principal when different;
- task/delegation context;
- runtime or workload identity;
- session and security-domain context.

Agent authorization MUST evaluate the intersection of delegating-principal authority, Agent-specific authority, task-scoped authority, runtime security authorization, session/environment restrictions, and resource classification/handling rules.

An Agent MUST NOT automatically inherit every permission of the human who requested the work. Agent access MUST be independently revocable and time/scoped constrained.

Directory Groups are identity/provisioning objects. Teams are product/organizational objects. External groups MAY supply Team membership, but the platform MUST NOT expose every directory or security group as a Team by default.

## CLS-001 — Generic security-label model

The platform MUST implement a versioned `SecurityLabel` model with:

```text
profile_id
sensitivity_level
handling_regimes[]
categories[]
compartments[]
dissemination_controls[]
releasable_to[]
originator
export_controls[]
derivation_sources[]
classification_authority
declassification_or_review_instructions
version
```

Security-label profiles are signed, versioned policy bundles. They are not free-form administrator fields.

Profiles MUST be declarative, schema-validated, deterministic, and offline-verifiable. They MUST define or reference their sensitivity vocabulary, handling regimes, categories/subcategories, compartments, dissemination controls, releasability, export controls, presentation/marking rules where applicable, normalization, dominance and join semantics, lowering/declassification/decontrol requirements, and mapping provenance. Semantic extensions are limited to the closed Stead profile-rule contract: typed monotone implications, incompatibilities, sensitivity and required-dimension constraints, trusted-context requirements, and registry mappings. Unknown rule kinds, fields, operators, references, contradictions, or non-monotone effects deny activation. Profiles MUST NOT be arbitrary executable plugins or a user-defined policy language.

Stead code MUST treat `profile_id` as a stable data identifier and MUST NOT give a particular profile ID privileged semantics. Approved profiles appropriate to an installation MAY be installed without changing the canonical ontology or application code. Maintained starter/reference profiles MAY be shipped for testing and evaluation, but they are not exhaustive definitions of an industry, government, regulatory, or classified-information regime.

## CLS-002 — Security-label policy profiles and external-regime mappings

The generic profile mechanism MUST support ordinary business sensitivity, regulated and CUI environments, and high-assurance, classified, or specialized vocabularies without a Stead fork or profile-specific authorization branch.

A maintained profile that claims to represent an external regulatory, handling, or classification regime MUST identify authoritative sources, scope, mapping version, provenance, tested coverage, and known limitations. Every claimed mapping MUST bind an exact source version/snapshot and content digest, mapping provenance identity, and digest-bound test evidence included in the signed activation material; a live URI is only a locator. It MUST NOT imply coverage beyond the mappings and tests actually supplied. Framework expressiveness or installation of a profile MUST NOT itself be described as completeness, compliance, accreditation, authorization to operate, cross-domain approval, or cryptographic validation.

Completing every possible external vocabulary is not a prerequisite for the core product. New approved profiles MUST remain data governed by the same closed schemas, signed activation, central evaluator, UI rendering contract, and release gates.

## CLS-003 — Deployment security domain

Every installation MUST define:

- security-domain identifier;
- allowed security-label profiles with one unambiguous ceiling for each permitted profile/version;
- trusted identity, attribute, runtime-attestation, profile, and signing authorities;
- allowed external integrations;
- allowed notification channels;
- allowed storage and backup destinations;
- allowed runner pools;
- network-zone and egress requirements;
- required signature threshold, custody/separation rules, and approved cryptographic boundary; and
- other environment-specific assurance controls needed by the deployment.

A resource whose label exceeds the ceiling for its own profile MUST be rejected. An unknown profile, missing or ambiguous profile ceiling, or cross-profile composition MUST fail closed. Cross-profile composition remains prohibited unless an explicitly signed and approved compatibility/bridge rule covers the exact profiles, versions, direction, operation, mapping semantics, trust binding, and non-weakening evidence; such a rule never creates a built-in cross-domain or write-down path. The v0.1 deployment-domain contract accepts no bridges; a non-empty bridge set requires a separately approved contract/ADR and complete negative evidence before any consumer may accept it.

## CLS-004 — Container boundary rules

Repository, tracker repository, docs repository, package namespace, runner pool, cache, artifact store, and backup set are security boundaries.

A repository MUST have one effective security label/security domain for access-control purposes.

Per-item labels MAY add handling markings, but they MUST NOT grant finer access than the enclosing cloneable/provider container can enforce.

When access differs, create a separate repository/project/security container.

## CLS-005 — Label inheritance and downgrade

New resources inherit the Project/container default label.

Derived resources use the least-upper-bound/join of all applicable source labels and explicit markings.

A label may be raised through an authorized workflow.

Lowering, declassifying, decontrolling, or removing a compartment/handling restriction MUST:

- be denied by default;
- require an authorized classification/security role;
- require a written reason and source authority;
- be fully audited;
- require the signature/approval threshold and separation of duty selected by the applicable signed profile and deployment security-domain policy, including two-person approval where required;
- invalidate caches, search projections, notifications, and exports;
- trigger reindex/reconciliation.

## CLS-006 — No unauthorized existence leakage

Authorization/classification MUST apply to:

- search results;
- search counts and facets;
- autocomplete;
- Team rollups;
- Project rollups;
- navigation, including capability-derived destinations, counts, and badges;
- activity feeds;
- graphs and relationship counts;
- notifications;
- email/webhook content;
- comments and mentions;
- repository lists;
- package/artifact metadata;
- audit views;
- exports;
- API errors.

Unauthorized users MUST NOT learn a protected resource’s title, identifier, existence, relationship count, or snippet unless policy explicitly permits existence-only disclosure.

## CLS-007 — Direct Git and provider paths

The authorization design MUST account for every non-UI path:

- Git over SSH;
- Git over HTTPS;
- Git LFS;
- Gitea REST/API tokens;
- package registry;
- artifact download;
- CI runner callbacks;
- object storage;
- webhooks.

Repository-level permissions MUST be reconciled from the central authorization model to Gitea.

Contextual restrictions that Gitea cannot evaluate directly MUST be enforced by an access gateway, network/security-domain controls, credential issuance, or a documented equivalent.

The product MUST NOT claim readiness for any regulated, classified, or specialized regime until the exact mapped profile, deployment controls, and bypass tests prove that direct provider paths cannot exceed the central policy. Framework capability alone is not such evidence.

## CLS-008 — Cross-domain prohibition

The core product MUST deny and not automate cross-domain or write-down transfer.

Export from a higher sensitivity/classification to a lower domain requires an external accredited process or cross-domain solution.

The platform may integrate with such a system through an audited export interface, but the integration is not part of the initial core release.

---

# 11. Events, NATS, activity, inbox, and audit

## EVT-001 — NATS from the beginning

NATS with JetStream MUST be included in the baseline architecture from the first vertical slice.

PostgreSQL remains the authoritative data store. NATS provides decoupling, durable delivery, replay, work distribution, and asynchronous scaling.

## EVT-002 — Transactional outbox

Every domain mutation that must emit an event MUST write the domain change and an outbox record in the same PostgreSQL transaction.

A worker publishes the outbox record to NATS and marks it delivered.

The platform MUST NOT use “write database, then directly publish” as the reliability model.

## EVT-003 — Event contract

Every event MUST:

- use a CloudEvents 1.0 envelope;
- have a versioned event type;
- have a JSON Schema;
- be documented in AsyncAPI;
- include organization, security-domain, security-label reference, correlation ID, causation ID, actor, source, and subject;
- minimize protected content in the event payload;
- support idempotent consumption;
- have defined retention and replay behavior.

Required naming pattern:

```text
stead.<domain>.<action>.v<major>
```

Example:

```text
stead.workitem.updated.v1
```

## EVT-004 — Delivery semantics

The platform assumes at-least-once delivery.

Every consumer MUST be idempotent.

Every durable side effect MUST use an idempotency key or processed-event record.

Failed events MUST enter a dead-letter stream with diagnostic context and controlled replay.

No consumer may assume global event ordering. Ordering requirements must be scoped to a resource or stream key.

## ACT-001 — Unified activity

The platform MUST convert domain/provider events into a canonical human activity model based on ActivityStreams concepts:

```text
Actor → Verb/Action → Object → Target
```

The activity feed is a projection and can be rebuilt.

Activities MUST retain canonical deep links and classification metadata.

## NOTIF-001 — Unified inbox

The in-app inbox is the canonical notification record.

Notification sources include:

- mentions;
- assignments;
- review requests;
- watched-resource changes;
- comments/replies;
- team/project ownership;
- build/deployment failures;
- release approvals;
- policy/security events.

Notifications MUST be grouped by resource and thread to avoid event spam.

Each notification MUST store:

- source event;
- recipient;
- reason;
- actor;
- resource;
- security label;
- read/archive state;
- created time;
- canonical deep link.

## NOTIF-002 — External channels

Email, Teams, Slack, and generic webhooks MUST be adapters behind a `NotificationChannel` interface.

The in-app inbox MUST work without any external service.

Security profiles MAY prohibit external channels.

External notifications MUST be redacted or reduced to a generic “protected update available” message when the channel is not authorized for the resource label.

## AUD-001 — Platform-wide audit

The platform MUST provide its own audit system and MUST NOT depend on Gitea Enterprise audit features.

Audit coverage includes:

- authentication events;
- authorization decisions and policy changes;
- identity/group/attribute changes;
- project/team/repository permission changes;
- security-label changes;
- issue/work/document mutations;
- Git push and pull-request events;
- package/artifact/release access;
- CI runner and secret use;
- administrative changes;
- export/import;
- backup/restore;
- integration/webhook changes.

## AUD-002 — Audit record requirements

Audit records MUST be append-only and contain:

- immutable record ID;
- timestamp;
- actor and authentication context;
- action;
- resource and effective security label;
- outcome;
- source IP/network/device context when available;
- request/correlation/causation IDs;
- policy/model versions;
- before/after hashes or controlled deltas;
- origin service/provider.

Sensitive content and secrets MUST NOT be copied into audit logs unnecessarily.

Audit partitions SHOULD be hash-chained with periodically signed checkpoints to provide tamper evidence.

Audit export MUST support object storage, syslog, and SIEM/webhook adapters.

---

# 12. Search and work graph requirements

## SRCH-001 — Unified search

Global search MUST cover authorized:

- Projects;
- Work Items;
- Documents;
- Repositories;
- code symbols and files where enabled;
- Pull Requests;
- commits;
- builds;
- releases;
- artifacts/packages;
- people and teams.

Results MUST be grouped by resource kind and use canonical links.

## SRCH-002 — Search providers

A `SearchProvider` interface is required.

Baseline profile:

- PostgreSQL full-text search and optional pgvector-compatible semantic indexing.

Scale profile:

- OpenSearch.

Search is a projection and MUST be fully rebuildable from authoritative stores and events.

## SRCH-003 — Authorization-aware indexing and querying

Search indexes MUST include organization, security domain, container, and security-label metadata.

The search service MUST apply coarse partition/scope filtering before retrieval and authoritative OpenFGA/policy-decision filtering before returning results, counts, facets, snippets, or suggestions.

Post-filtering alone is insufficient if it leaks totals or protected metadata.

Classified/security-domain profiles SHOULD use physically or logically separated indexes per domain where required.

## GRAPH-001 — Work graph

The platform MUST maintain a queryable graph projection of canonical resources and typed relationships.

The graph MAY use PostgreSQL relational tables initially. A graph database is not required.

Graph edges inherit the maximum/effective security restrictions of their endpoints and relationship metadata.

The graph MUST support:

- “related work/docs/code/PR/build/release” panels;
- impact and dependency traversal;
- provenance queries;
- search enrichment;
- migration reconciliation;
- AI/MCP access under the same authorization rules.

## GRAPH-002 — MCP, A2A, and agent access

The platform SHOULD expose an MCP server for permission-aware search, read, and controlled write operations.

The MCP server MUST call the same platform API and authorization service as human clients.

The platform SHOULD use A2A for registration and communication with replaceable external agent runtimes. The platform MUST NOT require one model provider, agent SDK, orchestration framework, or hosted AI service.

The Agent Registry SHOULD ingest or map A2A Agent Card semantics. Assigning a Work Item to an Agent MUST create a separately auditable Agent Run rather than overloading Work Item status with runtime state.

Agents MUST NOT receive direct unrestricted repository, database, OpenSearch, NATS, or object-store access. Direct Git protocol access is permitted only through narrowly scoped, short-lived credentials and provider enforcement.

All agent actions and writes MUST record the acting Agent, initiating/delegating principal where applicable, task context, correlation/causation IDs, and effective security context.

---

# 13. Attachments, object storage, packages, and artifacts

## STOR-001 — BlobStore interface

All platform-managed attachments and large binary objects MUST use a `BlobStore` interface with implementations for:

- local filesystem;
- S3-compatible storage;
- Azure Blob Storage;
- Google Cloud Storage.

The domain model and UI MUST be provider-independent.

## STOR-002 — Object requirements

Every object MUST have:

- stable ID;
- content hash;
- size;
- media type;
- owner/container;
- security label;
- creation provenance;
- retention policy;
- malware-scan status when a scanner is configured;
- provider locator hidden from normal clients.

Downloads MUST be authorized through the platform or short-lived provider URLs whose lifetime and scope are policy controlled.

## STOR-003 — Security partitioning

Objects, caches, temporary files, and backups MUST be partitioned by organization/security domain and, where required, sensitivity/classification.

Cross-domain shared caches are prohibited.

## ART-001 — OCI and package integration

Container images and portable release artifacts MUST use OCI-compatible distribution where applicable.

The UI MUST unify Gitea packages, Actions artifacts, release attachments, and platform BlobStore metadata without requiring users to understand separate storage systems.

---

# 14. CI/CD and software-supply-chain requirements

## CICD-001 — Gitea Actions

Gitea Actions is the initial workflow engine.

The platform MUST provide:

- workflow visibility in the unified UI;
- approved internal action catalog;
- organization/team/project workflow policy;
- runner-pool management;
- secret-provider integration;
- artifact, SBOM, provenance, and release linking;
- work-item and pull-request traceability.

## CICD-002 — Approved action catalog

Secure profiles MUST NOT fetch arbitrary third-party actions from the public internet at runtime.

Actions MUST be mirrored internally and pinned by immutable commit/digest.

The platform SHOULD ship maintained, permissively licensed building blocks for checkout, common language builds, tests, container builds, SBOM generation, signing, security scanning, and deployment hooks.

## CICD-003 — Runner security

Runners MUST be ephemeral by default.

Runner requirements:

- isolated job environment;
- nonprivileged/rootless execution where feasible;
- separate pools by organization/security domain/classification;
- no cross-project cache by default;
- egress deny-by-default in secure profiles;
- short-lived job credentials;
- secrets injected only for the job and redacted from logs;
- cleanup verification;
- resource limits;
- auditable image and configuration;
- no direct access to higher-classification storage from lower pools.

Privileged runners require an explicit policy exception and dedicated pool.

## CICD-004 — Supply-chain outputs

Every official platform release MUST provide:

- SPDX 3.0 SBOM;
- signed OCI images and Helm charts;
- SLSA-compatible provenance;
- checksums;
- third-party notices;
- vulnerability scan report;
- reproducible or documented deterministic build process where feasible.

The project MUST NOT claim a SLSA level or FIPS validation until the exact process/build satisfies that claim.

## CICD-005 — Secrets

A `SecretProvider` interface MUST support:

- Kubernetes Secrets for development/basic profiles;
- external secret stores through adapters;
- cloud KMS/vault integrations without making one provider mandatory.

Secrets MUST never be stored in Git, event payloads, logs, search indexes, or frontend state.

---

# 15. Migration and compatibility requirements

## MIG-001 — Migration is a product subsystem

Migration MUST be implemented as a resumable, idempotent subsystem with UI and CLI support, not a collection of one-off scripts.

Initial sources:

- GitHub repositories, issues, pull requests, releases, and selected Actions metadata;
- Jira projects, issues, comments, attachments, links, users, and status history;
- Confluence spaces, pages, hierarchy, attachments, links, and supported macros.

## MIG-002 — Migration stages

The migration workflow MUST support:

1. discovery/inventory;
2. source capability analysis;
3. identity mapping;
4. organization/team/project mapping;
5. ontology mapping;
6. security-label mapping;
7. dry run;
8. initial import;
9. validation/reconciliation;
10. optional delta synchronization;
11. cutover;
12. source read-only transition;
13. permanent redirect mapping;
14. final report.

## MIG-003 — Preservation

Migration MUST preserve, where technically available:

- original source ID/key;
- author identity mapping;
- timestamps;
- comments;
- attachments;
- issue links;
- page hierarchy;
- commit/PR references;
- source URL;
- original type/status in namespaced metadata;
- migration provenance.

Unsupported constructs MUST be listed explicitly and MUST NOT be silently discarded.

## MIG-004 — Canonicalization

Imported custom workflows and types MUST map to the fixed canonical model.

The import report MUST show every mapping and exception.

Legacy values may remain visible as source metadata but cannot create new platform semantics.

## MIG-005 — Redirects and compatibility

The platform MUST maintain a redirect map so historical Jira, Confluence, and GitHub links can resolve to canonical platform resources after cutover.

A limited compatibility gateway MAY later implement common legacy API calls, but this is not required for the first production release.

---

# 16. Deployment and installation requirements

## DEP-001 — Supported installation profiles

`steadctl install` MUST support these profiles:

### `local`

For evaluation, development, and small trusted installations.

- Docker Compose or compatible runtime
- bundled PostgreSQL
- bundled NATS
- bundled OpenFGA
- bundled deterministic policy evaluator implementing the policy-decision contract
- bundled Gitea
- filesystem BlobStore
- local bootstrap identity allowed
- PostgreSQL search
- no HA claim

### `kubernetes-standard`

For normal production.

- Helm deployment
- bundled or external PostgreSQL
- NATS JetStream
- OpenFGA and a deterministic evaluator implementing the policy-decision contract
- external OIDC recommended/required
- filesystem/PVC or external object storage
- PostgreSQL search or OpenSearch
- optional HA
- ingress/TLS integration

### `enterprise-external-services`

For organizations using managed/existing services.

- external PostgreSQL
- external object store
- external OIDC/SCIM
- optional external OpenSearch
- optional external secret store
- NATS bundled or external
- no cloud-specific requirement

### `high-assurance-airgap`

For isolated or high-assurance environments, whether commercial, regulated, government, classified, or specialized.

- offline OCI image/chart bundle
- no outbound network dependency
- signed artifacts and offline verification material
- one or more explicitly approved signed security-label profiles
- profile-driven classification/handling banners and markings where required
- strict external-integration allowlist
- deployment-policy-selected cryptographic boundary, including a FIPS-capable option where required
- separate runner and storage domains
- OSCAL component/control artifacts
- backup/export destinations explicitly approved

## DEP-002 — Guided install flow

The default interactive installation MUST ask no more than these decision groups:

1. Docker/local or Kubernetes
2. connected or air-gapped
3. identity provider choice
4. approved security-label profile set and deployment security-domain/assurance policy
5. bundled or external database/storage/search
6. hostname/TLS inputs

All other values use validated defaults and may be changed later through advanced configuration.

Required commands:

```text
steadctl install
steadctl status
steadctl doctor
steadctl config show
steadctl upgrade
steadctl backup
steadctl restore
steadctl export
steadctl airgap bundle
```

## DEP-003 — Helm

The project MUST publish one primary Helm chart with subcharts or external-service switches.

The chart MUST:

- include a JSON schema for values validation;
- have secure defaults;
- support disabling bundled dependencies;
- support existing secrets;
- support standard Ingress and storage classes;
- avoid cloud-specific CRDs in the core chart;
- include Helm tests;
- support amd64 and arm64 images;
- support Kubernetes version compatibility documented per release.

## DEP-004 — Air gap

An air-gap bundle MUST include:

- all required OCI images;
- Helm charts and/or Compose files;
- image digests;
- signatures and verification keys/bundles;
- SBOMs;
- third-party notices;
- database migrations;
- internal action catalog;
- install/upgrade scripts;
- offline documentation;
- vulnerability and known-issue manifest.

A high-assurance air-gap install MUST make no unapproved network call.

## DEP-005 — Upgrade behavior

`steadctl upgrade` MUST:

1. detect current versions;
2. validate target compatibility;
3. run health and capacity preflight;
4. create or verify a backup;
5. show planned migrations;
6. apply expand/contract-compatible migrations;
7. upgrade services in safe order;
8. run smoke and contract tests;
9. support rollback when data migrations permit;
10. produce an audit record and upgrade report.

---

# 17. Operations, backup, restore, and observability

## OPS-001 — OpenTelemetry

All platform services MUST emit OpenTelemetry-compatible:

- traces;
- metrics;
- structured logs;
- context propagation;
- correlation/request IDs.

OTLP export MUST be supported without requiring a specific observability vendor.

Sensitive content, secrets, document bodies, issue bodies, and classified data MUST NOT enter telemetry by default.

## OPS-002 — Health and diagnostics

Every service MUST expose:

- liveness;
- readiness;
- dependency health;
- version/build information;
- migration status;
- metrics.

`steadctl doctor` MUST check:

- DNS/TLS;
- database connectivity and schema;
- Gitea API compatibility;
- NATS streams/consumers;
- OpenFGA model;
- policy-decision bundle;
- object storage;
- search;
- identity provider;
- runner pools;
- backup status;
- license/signature integrity.

## OPS-003 — Backup

A backup MUST capture a consistent recoverable state for:

- platform PostgreSQL data;
- OpenFGA data;
- Gitea database;
- Git repositories;
- Git LFS;
- Gitea packages/actions artifacts where used;
- platform BlobStore;
- configuration and policy bundles;
- encryption/key references;
- redirect and migration maps;
- audit records.

NATS streams may be backed up for operational continuity, but the product must be recoverable from authoritative stores and outbox/reconciliation even if event history is unavailable.

## OPS-004 — Restore testing

Every release MUST pass an automated backup-and-restore test using generated representative data.

The restored system MUST preserve IDs, relationships, permissions, security labels, Git hashes, document history, work items, attachments, audit records, and canonical URLs.

## OPS-005 — Reliability targets

For the production Kubernetes profile, the initial targets are:

- 99.9% monthly availability for interactive platform APIs when deployed in documented HA mode;
- no acknowledged domain write lost after a single application/worker failure;
- interactive metadata read p95 at or below 300 ms under the published standard benchmark;
- interactive metadata write p95 at or below 500 ms excluding long Git/build operations;
- global search p95 at or below 1.5 seconds under the published scale benchmark;
- event-to-search/inbox propagation p95 at or below 5 seconds;
- graceful degradation when search, notification adapters, or analytics are unavailable.

The performance workstream MUST publish exact benchmark datasets and load shapes so these targets are reproducible.

---

# 18. Security engineering and licensing requirements

## SEC-001 — License policy

New original platform code MUST use Apache License 2.0 unless an ADR and legal review choose MIT for a specific package.

The Devlane-derived frontend MUST retain all required MIT notices.

Runtime and distributed dependencies are allowed by default only when licensed under a permissive license such as:

- Apache-2.0
- MIT
- BSD-2-Clause
- BSD-3-Clause
- ISC
- PostgreSQL License
- similarly permissive licenses approved by project policy

GPL, AGPL, SSPL, BSL, Commons Clause, proprietary, source-available, or field-of-use-restricted runtime dependencies are prohibited without explicit ADR and legal approval. The default answer is rejection.

CI MUST scan direct and transitive dependencies and fail on disallowed or unknown licenses.

## SEC-002 — Dependency and supply-chain controls

CI MUST perform:

- dependency vulnerability scanning;
- license scanning;
- secret scanning;
- SAST;
- container/image scanning;
- infrastructure-as-code scanning;
- SBOM generation;
- signature verification;
- pinned dependency/action checks.

Release images MUST use minimal bases, non-root users where feasible, read-only filesystems where feasible, dropped Linux capabilities, and explicit network requirements.

## SEC-003 — Cryptography

TLS MUST be supported for all network paths and required in production.

Encryption at rest is provided through database, filesystem, volume, object-store, or KMS integrations and MUST be documented per deployment security-domain policy.

An applicable deployment security-domain policy MAY require FIPS 140-3-validated cryptographic modules and approved algorithms. Stead MUST support such a selectable approved cryptographic boundary without keying behavior on a security-label profile name, and the project MUST NOT claim validation for an unvalidated exact build/module/configuration.

## SEC-004 — Threat modeling

Every major module and integration MUST have a threat model covering:

- trust boundaries;
- data flows;
- classification/security-domain flows;
- credentials;
- spoofing/tampering/repudiation/disclosure/denial/elevation risks;
- provider bypass paths;
- migration/import hazards;
- supply-chain hazards;
- recovery controls.

Threat-model findings become tracked requirements, not prose-only documentation.

## SEC-005 — OSCAL artifacts

The project MUST publish an OSCAL Component Definition describing how the platform supports relevant controls.

Where an approved deployment/security policy claims mappings to an external control regime, the project SHOULD provide scoped OSCAL implementation aids for the controls actually mapped and tested. A starter System Security Plan template and NIST SP 800-53 or NIST SP 800-171-related statements MAY be supplied when applicable.

These artifacts are implementation aids and MUST not claim an authorization outcome.

## SEC-006 — Privacy and telemetry

No outbound product analytics or telemetry is enabled by default.

Any opt-in telemetry MUST be documented, inspectable, removable, and unable to include protected content.

---

# 19. Testing and quality gates

## TEST-001 — Requirements traceability

The repository MUST contain a machine-readable matrix:

```text
requirement_id
implementation_modules
test_ids
documentation
status
release
```

A requirement cannot be marked complete without at least one acceptance test or an explicit reason an automated test is impossible.

## TEST-002 — Test layers

Required test suites:

1. unit tests;
2. property-based tests;
3. OpenFGA model tests;
4. policy decision-table, rule, property, and mutation tests;
5. schema tests;
6. provider contract tests;
7. module integration tests;
8. NATS/event replay and idempotency tests;
9. end-to-end browser tests;
10. accessibility tests;
11. security tests;
12. classification/non-disclosure tests;
13. performance/load tests;
14. migration tests;
15. upgrade compatibility tests;
16. Docker/Helm installation tests;
17. backup/restore tests;
18. chaos/failure tests;
19. fuzz tests for importers, webhooks, Markdown/frontmatter, and API parsers.

## TEST-003 — Coverage floors

Coverage is a floor, not proof of quality.

- Core Go domain modules: minimum 80% line and branch coverage.
- Authorization/classification modules: 100% policy-rule/decision-table coverage and at least 90% mutation score for critical policies.
- Provider adapters: minimum 80% coverage plus full contract-suite pass.
- Frontend: critical workflows require E2E coverage; component coverage targets are secondary.
- Every prior security or data-loss defect MUST gain a regression test.

## TEST-004 — Classification security matrix

The classification suite MUST test at least:

- lower sensitivity user denied higher resource;
- equal sensitivity without required compartment denied;
- equal sensitivity with compartment but no project need-to-know denied;
- project administrator without clearance denied;
- security officer can administer policy metadata without automatically reading content;
- expired clearance/attribute denied;
- label raise propagates to search, events, notifications, caches, attachments, and exports;
- downgrade requires configured approvals;
- direct Git clone/API/package access cannot bypass policy;
- unauthorized search counts, suggestions, graph edges, and inbox text reveal nothing;
- backups and logs inherit proper protection;
- lower-classification runner cannot receive higher-classification job or artifact;
- cross-domain export is denied.

## TEST-005 — Event tests

Event tests MUST prove:

- domain mutation and outbox write are atomic;
- publish retries do not duplicate outcomes;
- consumer restart resumes safely;
- dead-letter and replay work;
- out-of-order events do not corrupt state;
- schema compatibility is enforced;
- unauthorized consumers cannot subscribe to protected subjects;
- replay can rebuild search/activity projections.

## TEST-006 — Provider tests

The Gitea contract suite MUST cover:

- organizations, teams, users;
- repository create/read/update/archive;
- Git clone/push;
- issues/comments/labels/milestones;
- project boards/columns;
- pull requests/reviews;
- branch protection;
- webhooks and signature validation;
- Actions runs/artifacts;
- packages/releases;
- permission synchronization;
- migration/import;
- provider outage and rate/error handling.

Commonplace compatibility tests MUST cover:

- Gitea provider behavior;
- OKF parsing/writing;
- deterministic Markdown;
- document move/rename with stable IDs;
- concurrent edits and conflicts;
- review/publish;
- upstream-version compatibility.

## TEST-007 — Installation and upgrade tests

CI/release automation MUST test:

- fresh local Compose installation;
- fresh Kubernetes installation on a lightweight standard distribution;
- external PostgreSQL/object-store configuration;
- OpenSearch optional profile;
- air-gap install with network disabled;
- upgrade from every supported prior platform version;
- upgrade across every supported Gitea version;
- failed upgrade rollback/recovery;
- `steadctl doctor`;
- Helm chart tests and schema validation.

## TEST-008 — Security release gates

A release candidate fails if:

- any required test fails;
- a critical/high vulnerability lacks a documented time-bounded waiver;
- a disallowed/unknown distributed license is present;
- an image/chart/signature/SBOM is missing;
- authorization/classification model tests fail;
- backup/restore fails;
- install or upgrade tests fail;
- required audit events are missing;
- a known unauthorized disclosure path remains.

## TEST-009 — Golden general-work scenario

Every release MUST pass this organization-wide scenario without creating or linking a source-code repository:

1. Install with one supported command/profile.
2. Authenticate through the configured identity system.
3. Create an Organization, parent Team, child Team, and general Project owned by the child Team.
4. Confirm Team hierarchy does not grant unintended parent/child access.
5. Confirm automatic tracker repository, fixed board, managed labels, and Project docs repository creation.
6. Create Organization- or Team-scoped Knowledge and a Project Document.
7. Create a Work Item in the unified UI and connect it to the Project Document.
8. Embed a live Work view in the Document and confirm it reflects an authorized Work Item update without copied data.
9. Receive one unified inbox notification and see one unified activity timeline.
10. Search once and retrieve authorized Team, Project, Work, and Knowledge results.
11. Confirm Code and Delivery are absent from the Project UI.
12. Verify an unauthorized or insufficiently cleared user receives no metadata, count, suggestion, notification, or relationship leakage.
13. Back up and restore the installation.
14. Upgrade Gitea/platform within the supported matrix.
15. Repeat the key read/write/search/authorization checks.

## TEST-010 — Golden software-capability scenario

Every release that includes software capabilities MUST additionally pass:

1. Create a software Project or activate the approved software capability bundle.
2. Create/link a code repository and confirm Code and Delivery appear without changing the universal shell.
3. Create a branch/commit/Pull Request that references a Work Item and Document.
4. Request review and receive a unified inbox notification.
5. Merge the Pull Request and confirm activity, graph, and search updates.
6. Run a Gitea Action and link Build, SBOM, Artifact, Package, and Release resources.
7. Search once and retrieve authorized Work, Docs, Code, Pull Request, Build, Artifact, and Release results.
8. Deactivate or restrict an optional capability and verify data is preserved and navigation is updated without authorization leakage.

---

# 20. Release phases and subagent workstreams

## Phase 0 — Architecture constitution and contracts

No feature implementation begins until these are approved:

- product principles;
- OWGP v0.1;
- canonical entity schemas, including PrincipalRef, Directory Group, Agent, Agent Run, Team hierarchy, and generic resource containers;
- Project capability schema and preset contract;
- security-label schema and lattice;
- OpenFGA model v0.1;
- policy-decision input/output contract;
- provider interfaces;
- OpenAPI skeleton;
- AsyncAPI/event naming;
- database ownership map;
- threat-model baseline;
- license policy;
- repository layout;
- information-architecture map and UX design constitution;
- general-work and software-capability golden scenario test plans.

## Phase 1 — Executable vertical slice

Deliver:

- monorepo/tooling;
- `stead-web`, `stead-api`, `stead-worker`, `steadctl`;
- local installation;
- OIDC/local bootstrap;
- OpenFGA plus deterministic policy-decision path;
- stock Gitea adapter;
- Organization, Directory Group binding, hierarchical Team, and Project;
- automatic tracker and Organization/Team/Project docs repository creation as required;
- the `general` and `software` Project presets;
- fixed Work Item workflow;
- one OKF document flow with typed Work relationship and live Work view;
- capability-driven navigation with no empty developer areas;
- generated Platform API client and server-state/query layer;
- initial shared design system, command palette, universal object surface, and classification chrome;
- NATS/outbox;
- basic activity/inbox;
- PostgreSQL search;
- audit;
- the complete TEST-009 general-work scenario;
- the minimal TEST-010 software-capability path through Code + Pull Request + Build.

Phase 1 MUST NOT implement agent runtime execution, orchestration, prompting, model hosting, agent memory, or A2A dispatch. Agent/Agent Run schemas, assignee rendering, authorization seams, and audit/event contracts MUST remain valid.

This phase validates architecture and product coherence. It is not production complete.

## Phase 2 — Pilot/Beta

Deliver:

- mature Devlane-derived unified UX and completed design-system extraction;
- global Knowledge and Team experiences;
- context-preserving object peek/sheets and cross-resource relationship surfaces;
- Commonplace upstream integration or approved fallback;
- real document review;
- classification profiles and banners;
- complete search/work graph;
- CI Actions visibility and secure runners;
- BlobStore providers;
- email/webhook adapters;
- Agent Registry, MCP tool catalog, A2A dispatcher, task-scoped credentials, assignment, and Agent Run UI;
- GitHub/Jira/Confluence migration preview and initial import;
- Kubernetes/Helm profile;
- backup/restore;
- Gitea compatibility matrix;
- performance baseline;
- accessibility AA pass for critical flows.

## Phase 3 — Production 1.0

Deliver:

- real-time document collaboration;
- high-assurance air-gap profile;
- FIPS-capable configuration;
- OSCAL artifacts;
- full migration/cutover/redirect workflow;
- OpenSearch scale profile;
- HA guidance and tests;
- tamper-evident audit;
- supply-chain outputs/signatures/provenance;
- production SLO validation;
- security assessment and remediation;
- complete operator/user/contributor documentation.

## Required subagent workstreams

The project-manager agent MUST create separate workstreams with explicit interface ownership:

1. **Architecture and standards**
   - OWGP, schemas, ADRs, API/event contracts, ontology governance.

2. **Platform core/domain**
   - modular Go core, database boundaries, transactional operations, outbox.

3. **Gitea/provider integration**
   - adapter capabilities, tracker repos, reconciliation, compatibility matrix.

4. **Knowledge/Commonplace**
   - Gitea provider upstream work, OKF, editor, collaboration, review workflow.

5. **Unified frontend/design system**
   - Devlane fork, design constitution, capability-driven shell, universal object surfaces, global Knowledge, Team hierarchy views, shared editor/components, accessibility, visual regression.

6. **Identity/authorization/classification**
   - OIDC/SCIM, OpenFGA, the policy-decision layer, generic signed security-label profiles, deployment security domains, bypass testing.

7. **Events/activity/inbox/audit**
   - NATS, CloudEvents, AsyncAPI, notifications, audit, replay.

8. **Search/work graph/agent access**
   - PostgreSQL/OpenSearch providers, graph projection, MCP, A2A contracts, Agent Registry/Run integration, authorization filtering.

9. **CI/runners/artifacts/secrets**
   - Gitea Actions, runner isolation, internal actions, SBOM/provenance/signing.

10. **Storage**
    - BlobStore implementations, attachment security, retention, export.

11. **Migration**
    - GitHub/Jira/Confluence connectors, mapping, dry run, sync, redirects.

12. **Installation/operations**
    - steadctl, Compose, Helm, air gap, upgrades, backup/restore, OTel.

13. **QA/security/release**
    - traceability, test harnesses, threat testing, load, accessibility, release gates.

Each workstream MUST receive:

- owned directories;
- owned contracts;
- prohibited dependencies/boundaries;
- assigned requirement IDs;
- required tests;
- dependency milestones;
- security/classification considerations;
- definition of done.

---

# 21. Locked architecture decisions

These decisions are locked and require an ADR plus project-owner approval to change:

1. Stock Gitea; no fork and no direct database access.
2. Devlane-derived frontend is the primary UI fork.
3. No permanent Commonplace fork.
4. Go backend/worker/CLI and React/TypeScript frontend.
5. PostgreSQL as authoritative platform relational store.
6. NATS JetStream from the beginning.
7. Transactional outbox for reliable domain events.
8. OpenFGA for relationship authorization.
9. A separate deterministic classification/context/information-flow policy layer, with its implementation selected by ADR.
10. Git + Markdown + OKF for documentation.
11. Fixed canonical workflow and ontology, including universal `deliverable`, `task`, and `problem` Work Item semantics.
12. Dedicated Gitea tracker repository per Platform Project.
13. Repository/container-level classification boundary.
14. OpenAPI, JSON Schema, CloudEvents, AsyncAPI, OTel, OCI, SPDX, SLSA, OSCAL standards stack.
15. Docker/local and Helm/Kubernetes first-class deployment.
16. No required cloud service.
17. No built-in cross-domain transfers.
18. Essential security remains in the open-source distribution.
19. Apache-2.0 for newly authored core code unless specifically approved otherwise.
20. No unapproved source-available or copyleft runtime dependency.
21. Work + Docs are universal; software-delivery capabilities are additive and capability-driven.
22. Universal global navigation is Home, Inbox, My Work, Projects, Knowledge, and Teams; Search is omnipresent rather than a destination.
23. Project primary areas are limited to Overview, Work, Docs, optional Code, and optional Delivery.
24. Team hierarchy is single-parent, cycle-free, maximum twelve levels, and does not implicitly grant authorization.
25. Every Project has exactly one owning Team and may have contributing Teams.
26. Documents may be Organization-, Team-, or Project-scoped; Work Items remain Project-scoped.
27. User, Agent, Service Principal (`service_account`), and Directory Group are distinct principal/reference types; acting principals are users, agents, or service accounts, and agent runtimes remain external and replaceable.
28. MCP is the agent-to-platform tool/data boundary; A2A is the preferred external agent-runtime interoperability boundary.
29. Project lifecycle states are planned, active, paused, completed, and canceled; archive is separate and reversible.
30. Canonical document types use universal semantics; software-specific names are display labels only.

---

# 22. Definition of done

A feature is done only when all applicable items are true:

- requirement IDs are linked;
- implementation respects module/provider boundaries;
- API/event/schema contracts are updated;
- authorization and classification decisions are implemented server-side;
- direct-provider bypass paths are covered;
- unit, contract, integration, E2E, security, and regression tests pass;
- observability is present without sensitive leakage;
- audit events are present;
- migration and backward compatibility are addressed;
- installation/upgrade behavior is addressed;
- backup/restore implications are addressed;
- accessibility is addressed;
- general and software capability presentations are tested where applicable;
- no irrelevant capability or unauthorized metadata is exposed;
- documentation is complete;
- licenses and SBOM are clean;
- independent QA/security review passes;
- no unresolved critical/high defect remains;
- golden scenario remains green.

---

# 23. Final project-manager instruction

Do not decompose this project as “build a Jira clone,” “build a Confluence clone,” and “install Gitea.”

Decompose it as one platform with a canonical work graph and shared cross-cutting systems.

The first technical milestone must prove a thin universal slice and its additive software extension without changing the shell or canonical model.

Universal general-work slice:

```text
one identity
+ one authorization decision
+ one parent/child Team hierarchy with no implicit authorization
+ one general Project owned by one Team
+ one Gitea-backed Work Item
+ one Organization/Team-scoped Git/OKF Document
+ one Project-scoped Git/OKF Document with a live Work view
+ one event stream
+ one inbox
+ authorized Team/Project/Work/Knowledge search results
+ one audit trail
+ one simple installation
+ no Code or Delivery surface
```

Additive software-capability extension:

```text
the same identity, authorization, shell, Project, Work, Docs, events, inbox, search, and audit contracts
+ one code repository and Pull Request
+ one Build, Artifact, Package, and Release path
+ capability-driven Code and Delivery surfaces
```

Only after TEST-009 and the applicable TEST-010 path pass should agents expand feature depth in parallel.

---

# 24. Approved agent-ready architecture requirements

These requirements preserve compatibility with future agent functionality. They require Phase 0 schemas, authorization/audit seams, interface boundaries, and test contracts, but do not add agent execution to Phase 0.

## AGENT-001 — Generalize identity to principals

All new domain, authorization, audit, event, and assignment contracts MUST distinguish between human identity and acting principal.

The canonical acting-principal model MUST permit at minimum:

- `user`;
- `agent`;
- `service_account`.

`PrincipalRef` MAY additionally identify a non-acting `directory_group` for membership and authorization relationships. Code MUST NOT assume that an actor, assignee, creator, reviewer, subscriber, or request principal is necessarily a human user.

## AGENT-002 — Work-item assignment

Work-item assignment contracts MUST support an `agent` principal as an assignee.

Agent execution behavior is out of scope for Phase 0. Existing Gitea-backed issue assignment may continue to use Gitea-native users where required, but the Platform API and canonical model MUST NOT expose that provider limitation as the canonical assignment model.

## AGENT-003 — Authorization

The initial OpenFGA model MUST reserve `agent` as a first-class principal type.

The authorization architecture MUST support future agent-specific permissions, explicit delegation from users to agents, task-scoped authorization, revocation independent of the delegating user, and agent assignment to specific resources.

Classification policy inputs MUST identify principal type and MUST permit future evaluation of agent runtime, security-domain, classification-ceiling, compartment, model-provider, tool-scope, and execution-environment attributes.

No broad human permission inheritance for agents may be assumed.

## AGENT-004 — Audit and events

All audit and CloudEvents contracts MUST identify:

- acting principal;
- principal type;
- initiating user or principal when different;
- delegation/task context when present;
- correlation and causation identifiers.

The schema MUST allow a future action to record `requested_by = user:alice` and `actor = agent:backend-agent` without a schema change.

## AGENT-005 — Agent integration boundary

Agents MUST interact with canonical Platform resources through Platform APIs and the platform-wide MCP interface rather than relying directly on provider-specific business APIs.

Direct Git protocol operations against the configured SCM provider are permitted using narrowly scoped, short-lived, independently revocable credentials.

The architecture MUST remain compatible with external agent runtimes. The Platform MUST NOT require any particular AI model, agent SDK, orchestration framework, or model provider.

Interoperability SHOULD use MCP for agent-to-platform tools and data and A2A for platform-to-agent and agent-to-agent interoperability. The Agent Registry SHOULD use A2A Agent Card semantics where applicable.

## AGENT-006 — Classification

Agent authorization MUST be capable of evaluating the intersection of:

1. delegating principal authority;
2. agent-specific authority;
3. task-scoped authority;
4. runtime security-domain authorization;
5. session/environment restrictions; and
6. resource security classification and handling requirements.

Phase 0 need only preserve the data, model, policy, and test seams necessary to support this future behavior.

## AGENT-007 — Explicit Phase 0 non-goal

The project MUST NOT build agent orchestration, prompting, model hosting, agent memory, Agent Run execution, A2A dispatch, or the executable full MCP tool catalog during Phase 0 unless another approved requirement explicitly requires the specific capability.

Phase 0 MUST define the Agent, Agent Run, PrincipalRef, assignment, authorization, audit/event, MCP/A2A boundary, and external-runtime compatibility contracts required elsewhere in this directive. Those contract artifacts do not authorize execution.
