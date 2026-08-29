# Phase 0 License and Dependency Approval Workflow

| Field | Value |
|---|---|
| Status | Phase 0 approval candidate; approval required before adding product dependencies |
| Policy owner | Workstream 13 — QA/security/release |
| Technical reviewers | Workstream 1 — Architecture/standards; owning implementation workstream; Workstream 9 for actions/build supply chain; Workstream 12 for distributed images/charts |
| Exception authority | Legal reviewer + ADR approval + project-owner approval |
| Normative requirements | PRIN-002, PRIN-004, PRIN-008, PRIN-011; DOC-002; SCM-005; CICD-002/004; DEP-004; SEC-001–003; TEST-008; AGENT-005/007; locked decisions 1–3, 14, 16, 18–20 |

No dependency is approved merely because it is popular, open source, already present transitively, used only in CI, or accepted by an automated scanner. Approval is scoped to an exact package/source, version or version range, artifact kind, use, linkage/distribution mode, and owning module. Scope changes require review.

## License baseline

1. All newly authored core platform code uses Apache License 2.0.
2. MIT may be selected for a specific newly authored package only through an ADR and legal review. Because this changes locked decision 19 for that package, project-owner approval is also required.
3. The Devlane-derived frontend retains every required MIT license and copyright notice, including notices carried by modified files or distributions.
4. Stock Gitea remains stock and separately distributed/integrated through supported interfaces. No Gitea code is copied into a platform module and no Gitea fork is created.
5. Commonplace work is upstream-first. Any temporary patch series remains minimal, isolated, documented, tested, removable, and compliant with upstream license and notice obligations. It cannot carry platform ontology or authorization logic.
6. Third-party code, generated code, vendored assets, fonts, icons, models/data, actions, base images, charts, binaries, and copied snippets are dependencies for this policy; a package manager is not required for something to be in scope.
7. Copyright/license headers and notices are preserved. Removal, consolidation, or substitution occurs only when the applicable license and legal review permit it.
8. Future agent integration remains portable across external runtimes. Stead does not require a particular AI model, agent SDK, orchestration framework, model provider, or proprietary agent control plane; a dependency proposal cannot make one mandatory through convenience coupling.
9. Phase 0 does not add dependencies for agent orchestration, prompting, model hosting, agent memory, `AgentRun` execution, A2A dispatch, a future Agent Registry, or a full MCP tool catalog. A schema/test-only library is still subject to this workflow and must have a Phase 0 contract need.

The project license does not override third-party licenses. This workflow records obligations; it is not a substitute for legal advice.

## Default license categories

| Category | Examples / definition | Default disposition | Required action |
|---|---|---|---|
| `ALLOW-PERMISSIVE` | Apache-2.0, MIT, BSD-2-Clause, BSD-3-Clause, ISC, PostgreSQL License | Allowed for runtime and distribution when exact identity and obligations are verified | Automated scan, approval record, notices/attribution as required, SBOM inclusion, security review |
| `REVIEW-PERMISSIVE` | A similarly permissive license not yet on the exact allowlist; dual license with a permissible option | Not yet allowed | Legal confirms SPDX expression and obligations; policy owner adds a scoped approval before merge/distribution |
| `REVIEW-NONRUNTIME` | Build/test/development tool that is not linked, embedded, copied, vendored, installed in a release image, or distributed | Case-specific; never implicitly allowed | License and architecture review the actual use/output; record non-distribution boundary; scan and SBOM decision |
| `REJECT-DEFAULT` | GPL, AGPL, SSPL, BSL, Commons Clause, proprietary, source-available, or field-of-use-restricted runtime/distributed component | Rejected | Select an approved alternative or follow the exception process; the default answer is no |
| `UNKNOWN` | Missing, custom, conflicting, unparseable, `NOASSERTION`, unknown transitive license, or unverifiable source | Rejected and quarantined | Establish exact provenance/license through legal review or remove/replace |
| `FORBIDDEN-SOURCE` | Component whose acquisition/use violates its terms, has no redistribution right needed by the release, or cannot produce required notices/SBOM/provenance | Rejected | Remove and rebuild affected artifacts; no exception without an explicit lawful basis and all exception approvals |

“Runtime/distributed” includes anything installed in or needed by an image, chart, CLI binary, web bundle, air-gap bundle, installer, provider adapter, embedded database migration, action catalog, release artifact, or downloadable asset. Dynamic versus static linkage does not by itself decide approval.

An automated tool may classify a known exact license into an approved category, but it may not decide that a novel license is “similarly permissive,” resolve conflicting metadata, or approve an exception.

## Roles and separation of duties

| Role | Responsibility | May not |
|---|---|---|
| Requester / dependency owner | Supply complete intake, alternatives, exact use, tests, upgrade and rollback plan | Approve their own request or suppress scan findings |
| Module/contract owner | Confirm the dependency stays inside owned boundaries and does not replace a locked standard/interface | Waive licensing or security requirements |
| Architecture reviewer (WS-01) | Review necessity, portability, replaceability, interface, size/operational cost and ADR need | Give legal approval |
| Security/supply-chain reviewer (WS-09/13) | Verify source, signatures/checksums, vulnerability posture, maintenance and build provenance | Reclassify an unknown/restricted license as permissible |
| License policy steward (WS-13) | Validate scan output, obligations, approval registry, notices and SBOM evidence | Self-approve an exception they requested/implemented |
| Legal reviewer | Interpret license terms and approve or reject exception terms | Replace required architecture/project-owner approval |
| Project owner | Approve ADRs that change locked license/dependency decisions | Bypass TEST-008 release failures without bringing the dependency into an explicitly lawful, approved state |
| Independent release QA/security | Recompute and verify release evidence against approved records | Accept missing/unknown/disallowed distributed licenses |

## Approval record

The repository must carry a machine-readable, reviewable approval record for every direct dependency and every separately distributed third-party component. Transitive dependencies are inventoried by lockfile/SBOM and evaluated by policy; a transitive exception also receives its own record. The record must contain at least:

```yaml
approval_id: DEP-APP-unique-id
component:
  name: exact-name
  ecosystem: go-or-npm-or-oci-or-other
  source_url: canonical-upstream
  version: exact-version-or-bounded-range
  digest: immutable-digest-when-applicable
  license_expression: SPDX-expression
usage:
  owner: workstream-and-module
  directories: [owned/path]
  purpose: bounded-purpose
  relationship: runtime-or-build-or-test-or-vendored-or-service
  distributed_in: [artifact-identifiers]
  linkage_or_interface: description
decision:
  category: ALLOW-PERMISSIVE
  status: approved
  approvers: [independent-identities]
  approved_at: RFC3339
  expires_or_review_at: RFC3339-or-null
obligations:
  notices: [notice-identifiers]
  source_or_offer: none-or-description
  modifications: description
security:
  vulnerability_result: evidence-reference
  provenance_result: evidence-reference
  maintenance_risk: assessment
change:
  update_policy: bounded-policy
  rollback_version: exact-known-good-version
  rollback_constraints: description
adr: null-or-ADR-id
legal_approval: null-or-evidence-reference
```

Approval evidence must not contain credentials, private registry tokens, embargoed vulnerability detail that belongs in a restricted system, or unredacted personal data.

## Intake-to-approval workflow

```text
request
→ inventory and exact-source verification
→ license classification and obligation review
→ architecture/portability review
→ security, maintenance and provenance review
→ ADR + legal + project-owner exception path if needed
→ scoped approval record
→ lock/pin and integrate
→ CI verification, SBOM and notices
→ independent release verification
→ continuous update/revocation review
```

### 1. Request

Before code imports or generated/vendor output are committed, the requester records:

- exact component, upstream source, proposed version and immutable digest where available;
- owning workstream, module and directories;
- runtime, build, test, tool, action, service, asset, base-image, chart, or vendored relationship;
- how it is linked, invoked, modified and distributed;
- required capability and why existing approved code or a small original implementation is insufficient;
- transitive dependency inventory and lockfile impact;
- expected license expression, notices and attribution;
- supported platforms, air-gap effect and outbound/network behavior;
- vulnerability and maintenance posture, signing/provenance source, and project health;
- data handled, permissions/credentials needed, attack surface and security-domain implications;
- update owner, compatibility test, removal strategy, known-good rollback version, and state/data migration implications.

The dependency cannot enter product code while the request is incomplete. A proof-of-concept may exist only on an explicitly non-release branch or isolated scratch area and may not be distributed or merged.

### 2. Inventory and provenance verification

Resolve package aliases, forks, mirrors, vendored copies and transitive components to their canonical upstream and exact artifact. Verify checksums/signatures when published. Compare repository license files, package metadata, source headers and included `NOTICE`/attribution files. Conflicting or missing evidence sets the status to `UNKNOWN` and quarantines the component.

For containers, actions and external binaries, inspect the entire distributed/runtime contents rather than only the top-level project license. Tags are not immutable identity; pin an action by commit and an OCI artifact by digest for secure/release use.

### 3. License and obligation decision

The policy steward assigns one category from the table. Legal review is mandatory for custom terms, dual-license ambiguity, “similarly permissive” additions, unusual patent/trademark/data terms, conflicting evidence, or an exception. Obligations are written as verifiable outputs: license text, copyright attribution, `NOTICE` content, source/offer obligation if any, modification notice, user-interface attribution if required, and redistribution restrictions.

Approval of one version/use does not approve a differently licensed major version, a fork, an optional extra, a copied example, or a new distribution mode.

### 4. Architecture and security review

Architecture confirms that the dependency:

- does not change a locked architecture decision or canonical ontology without an approved ADR;
- does not access an upstream or another module’s database/internal files;
- is behind the required provider/module interface where applicable;
- remains replaceable, infrastructure-agnostic and usable offline where the profile requires;
- does not introduce an unbounded in-process plugin surface or required SaaS control plane;
- does not couple future Platform API/MCP interoperability to one external agent runtime, model, SDK, orchestration framework or model provider;
- does not expand Phase 0 into agent execution/orchestration/prompting/model hosting/memory/A2A dispatch/full MCP implementation;
- has a bounded operational footprint and compatibility/upgrade test plan.

Security verifies vulnerability history, supported versions, maintainer/release provenance, credential and network behavior, build scripts, transitive code, binary provenance, minimal privileges, incident response, and supply-chain scans. A license approval never implies a security approval.

### 5. Decision and exception path

For `ALLOW-PERMISSIVE`, all required non-legal reviews and the scoped record must be complete before merge. For `REVIEW-PERMISSIVE` and ambiguous terms, legal approval is required before the steward may issue the scoped approval.

For a `REJECT-DEFAULT` runtime/distributed dependency, the normal decision is rejection and selection of an alternative. Any proposed exception requires all of the following:

1. an ADR identifying the exact component/version/use and the locked decision affected;
2. alternatives considered and why each fails the requirement;
3. legal approval of the exact linkage, modification and distribution model;
4. impact analysis for project licensing, source/notice obligations, air-gap distribution, customer exitability, security, maintenance and replacement;
5. a containment/interface plan and removal trigger;
6. automated license/SBOM/notice tests and update/rollback behavior;
7. explicit project-owner approval.

An exception is narrow and does not add the license family to the general allowlist. A material version, term, usage or distribution change reopens review. No ADR may legalize use for which the project lacks rights.

### 6. Integration and pinning

After approval, the owner updates the appropriate manifest and deterministic lockfile, pins actions/images by immutable commit or digest, limits optional features to the approved set, and adds contract/security tests. Generated or vendored material retains provenance and is reproducibly refreshable. Runtime images contain only approved, required components.

No module may download executable code or arbitrary public actions at runtime. Secure profiles use the approved internal action catalog. Air-gap inputs must come from the signed, inventoried bundle.

### 7. CI policy gates

Every change and release candidate runs, as applicable:

- direct and transitive license scan with `UNKNOWN`, unapproved, or disallowed results failing;
- dependency vulnerability scan;
- secret scan and SAST;
- container/image and infrastructure-as-code scan;
- SBOM generation and diff against manifests/lockfiles/image contents;
- signature/checksum/provenance verification;
- unpinned dependency/action/image detection;
- third-party notice generation and completeness comparison;
- clean-room/reproducible or documented deterministic build check where feasible.

Scanner suppressions are versioned records with a reason, evidence, scope, owner and expiry. A suppression can correct a false identification; it cannot silently approve a license or vulnerability. CI policy/configuration changes receive code review by the policy owner and independent QA/security validation.

## SBOM and third-party notices

Each official release provides SPDX 3.0 SBOMs covering the contents of every distributed image, chart, CLI/archive, web bundle, air-gap bundle and other release artifact. The SBOM identifies packages/files as needed, versions, suppliers/sources, checksums, license expressions, dependency relationships and the artifact digest it describes. Where one aggregate SBOM is offered, component SBOMs and their exact relationship to the release remain discoverable.

Third-party notices are generated from approved records and verified against the actual release contents. They include all required license texts, copyright attributions, upstream `NOTICE` material and modification statements. The Devlane MIT notices are an explicit regression fixture. Apache-2.0 `LICENSE` and any applicable platform/upstream `NOTICE` material ship in source and distribution locations required by the packaging contract.

SBOM, notices, checksums, vulnerability/known-issue manifest, signatures and verification material are included in the government air-gap bundle. These artifacts contain no registry credentials, private source paths, secrets or protected customer data.

## Updates, rollback and revocation

### Routine update

A dependency update is a new approval evaluation, even when automation opens it. CI computes license, transitive, SBOM, notice, vulnerability, build-script, API/contract, binary provenance and image-size/privilege diffs. The owner runs module/provider contracts, supported-version compatibility, upgrade and rollback tests. Approval may be streamlined only when the existing record explicitly covers the new version range and every material check remains unchanged.

### Emergency security update

An emergency may shorten review elapsed time but does not skip license, provenance, signature, test, SBOM, notice, separation-of-duties or release requirements. If no safe approved update exists, disable/isolate the affected feature, roll back to a supported non-vulnerable version, or hold the release. A critical/high vulnerability waiver is governed by `release-gates.md`; it must be time-bounded and cannot waive a disallowed/unknown distributed license.

### Rollback

Every approved dependency has an exact known-good rollback target and records whether rollback is binary-only or constrained by schema/data/config migration. Release artifacts and lockfiles must permit rebuilding or retrieving the signed known-good digest. Rollback repeats signature, license, SBOM, vulnerability, compatibility and smoke checks. A rollback cannot reintroduce a revoked component or known unauthorized disclosure.

### Quarantine and revocation

Immediately quarantine a component or artifact when its license becomes unknown/disallowed for the use, provenance/signature fails, source is compromised, a material term changes, an approval expires, or a critical supply-chain event makes integrity uncertain. Quarantine means:

- block merge, build promotion, signing, release and air-gap inclusion;
- prevent new installation or runtime download;
- identify every affected direct/transitive artifact and release by SBOM/digest;
- preserve evidence without exposing secrets;
- remove/replace or obtain the full exception approvals;
- rotate credentials/signers and revoke signatures/attestations when implicated;
- rebuild from trusted inputs, regenerate SBOM/notices/provenance, and rerun all gates;
- publish an appropriate known-issue/remediation notice for already released artifacts.

Quarantined artifacts are not deleted until incident/legal retention needs and reproducible recovery are resolved.

## Required evidence and retention

For each release, retain the approval registry snapshot, manifests/lockfiles, raw scanner results, suppressions, vulnerability waivers, SBOMs, notice comparison, source and artifact digests, provenance, signatures, build identity, test results, exception ADR/legal/project-owner approvals, and quarantine/revocation actions. Evidence is immutable or tamper-evident, access-controlled, and linked to the release digest.

Independent QA/security recomputes the distributed-license result from the actual candidate. A release fails if any distributed component is unknown, disallowed, absent from its SBOM, missing required notices, or outside its approval scope; if any required supply-chain output is missing; or if signature/provenance verification does not bind to the candidate digest.

## Phase 0 acceptance criteria

This workflow is ready for architecture-constitution approval only when:

- project license and Devlane notice rules are ratified;
- exact allow/reject/unknown categories and the exception authority are approved;
- an approval-record schema and repository location have owners;
- CI checks, evidence formats, SBOM/notice generators and failure semantics have test IDs in the Phase 0 backlog;
- update, rollback, quarantine and already-released-component response are assigned;
- release gates consume the evidence without allowing implementation-owner self-approval.
- Phase 0 dependency proposals have been checked against AGENT-005/007 portability and non-goal constraints, with no agent runtime/model/SDK/orchestrator/provider made mandatory.
