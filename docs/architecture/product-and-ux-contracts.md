# Product and UX contracts

Status: **Phase 0 approval candidate**
Requirements: `PRIN-001`, `PRIN-013`, `PRIN-014`, `UX-001`–`UX-009`

## Information architecture

```text
Global: Home | Inbox | My Work | Projects | Knowledge | Teams
        Search/command is omnipresent; administration is separate.

Project: Overview | Work | Docs | [Code] | [Delivery]
Team:    Overview | People | Projects | Work | Docs
```

Code appears only when `scm` is active and authorized; Pull Requests live there. Delivery appears only for an active authorized delivery capability and contains Builds, Packages, Releases, Artifacts, and Deployments. Missing or denied capabilities contribute no tab, command, count, suggestion, notification, relationship summary, empty state, or URL discovery response. Activity is contextual and Settings is not a normal Project tab.

## Preset flows

| Preset | Creation result | Visible Project areas | Prohibited leakage |
|---|---|---|---|
| `general` | Work + Docs; one tracker repository is hidden implementation backing | Overview, Work, Docs | Code/Delivery concepts or repository setup language |
| `software` | Work + Docs + SCM + review + CI + packages + releases | Overview, Work, Docs, Code, Delivery as authorized | Provider routes/terminology; disabled deployment controls |
| `controlled_knowledge` | Work + Docs with controlled-review defaults and separate containers as needed | Overview, Work, Docs | New document ontology/workflow or implied page-level Git secrecy |

Presets cannot reorder navigation, redefine canonical values, grant access, or add primary tabs. Advanced provider settings occur after creation and only for authorized users.

## Universal object surface

Every major object has: canonical type/title; owner or responsible Team/principal; status where applicable; effective label plus text/icon handling; typed context strip; comments/activity/history where applicable; watch state; stable deep link; save/sync/version/provenance state; one primary action. A reusable side peek preserves list/document/search/filter context and offers full-page navigation. Blocking modals never stack.

One creation language, command palette, mention/reference grammar, editor behavior, keyboard vocabulary, and activity model serve Work, Docs, Teams, People, Agents, and optional delivery resources. Documents render live authorized Work queries rather than copied tables. The UI may display Feature/Bug or Architecture Decision/Runbook under the software preset, but API values remain universal.

## Design constitution

- Calm, focused, fast, cohesive, progressively disclosed, and low-concept; Linear is a quality benchmark, not the design target.
- Devlane is a permanent visual/component fork only. Its routes and Modules, Epics, Pages, Board, Intake, Archives, Drafts, or other ontology are not contracts.
- One primary action per state; no more than five Project areas; no nested modal; no empty developer surfaces.
- System/Light/Dark and restrained Organization branding only; no theme marketplace.
- Security is calm but unmistakable session/object/search/export/print chrome and never color-only.
- Pointer, keyboard, and screen-reader behavior are equivalent. Target WCAG 2.2 AA.
- Layout is stable while loading; primary authorized content precedes analytics/relationships.
- Responsive priority is content and actions: side navigation collapses, peek becomes full-height, tables gain semantic list fallback, and no action is pointer-only.

## Speed and capability delivery

Stead should feel local even when it is not. The shell acknowledges input immediately, preserves list/filter/scroll/selection state, safely prefetches authorized Peek content on hover/focus/selection, and uses optimistic rendering only with a safe rollback to the authoritative server result. Primary content precedes optional analytics; full-page reloads, nested modal stacks, avoidable skeletons, and layout shift are prohibited on normal flows.

After shell load, useful primary content normally comes from one composed Platform API/BFF request. Browser code never fans out to providers, OpenFGA, NATS, storage, or internal services. Cached/prefetched Peek and visible input acknowledgement target p95 at or below 50 ms; local command results target p95 at or below 30 ms; useful Project primary content targets 500 ms; and documented cold interactive targets one second. Client data is only a presentation optimization for the current authorized context and is cleared on logout, principal change, security-domain change, or another authorization-context change.

The universal eager JavaScript graph is at most 250 KiB gzip, excluding source maps and lazy capability chunks. Docs editor, Code, Delivery, Administration, Migration, and heavy analytics are lazy boundaries; diff, CI/build, package/release/deployment, migration/admin, full-editor, and charting code is not downloaded by a general HR or finance user. CI measures the eager entry graph. A measured exception requires a focused ADR and replacement budget.

## Component and ownership inventory

`WS-05` owns AppShell, CommandSearch, ResourceHeader, SecurityMarking, ContextStrip, ObjectPeek, CreateMenu, WorkView (List/Board/Timeline/Calendar/Triage presentations), DocumentEditorShell, ActivityThread, InboxThread, CapabilityNav, EmptyState, and generated API client binding. `WS-01` owns API/schema sources; `WS-06` owns policy semantics; domain owners own behavior behind Platform APIs. Icons are a single accessible set, never provider logos for canonical actions, and decorative icons are hidden from assistive technology.

## Low-fidelity journeys

```text
HR/nontechnical: Projects → New general → purpose/team → Overview → Work → Docs
  Assert: no Code/Delivery/repository vocabulary; create deliverable and procedure.

Developer: software Project → Work peek → linked specification → Code/PR → Delivery/build
  Assert: same header/context/activity vocabulary; provider stays hidden.

Project lead: Home attention → blocked Work → context strip → contributing Team → live Work view
  Assert: hierarchy rollup is authorized and preserves filters/context.

Knowledge author: Knowledge → Team container → edit procedure → convert text to Work → review
  Assert: stable ID/Git state/marking shown; live reference is authorized.

Security officer: policy administration → denied-rollup evidence → downgrade request → audit
  Assert: policy role does not grant content read; two-person workflow where profile requires.

Future Agent assignee: Work assignee picker → Agent identity → assignment/activity context
  Assert: visually distinct accessible principal; assignment grants no execution; no AI chat/runtime UI.
```

Phase 1 must produce executable low-fidelity prototypes, visual-regression screens, accessibility matrix, responsive specification, and user-test evidence before broad UI implementation. This Phase 0 contract fixes their semantics and ownership.

## Future-safe presentation constraints

- Request forms and intake are inputs/views that create canonical Work Items in `backlog`; Request, Intake, Service Desk Ticket, Triage, Board, Timeline, and Calendar are not new entities.
- Work approvals use explicit reviewer/checkpoint relationships and audit records rather than organization-specific workflow states.
- Responsive web prioritizes reading, search, inbox, comments, approvals, and basic Work updates; desktop remains the primary authoring and Code experience unless a later approved scope changes it.
- Analytics are action-oriented projections for blocked work, stale knowledge, review queues, delivery health, and operational risk. Individual surveillance scores and vanity productivity metrics are prohibited.
- Future Agent Run progress appears in Work/activity context, not a separate AI-chat application. No Phase 0 screen invokes a runtime.
