# Proposed amendment: reproducible local development policy bootstrap

Status: **PROPOSED — NON-OPERATIVE**

Owner decision required: explicit approval of this document's immutable Git commit.
This proposal does not activate a policy, change an accepted ADR, or grant a release waiver.

## Problem and exact affected decision

ADR-0006 requires a generated instance-local development key, verified signatures,
and a visibly non-production trust store. Its mandatory release evidence also
binds independent reviews to each exact policy bundle and completed archive.
The key and local OpenFGA model identity change those digests on every install.

The executable checks are `validateReviewsAndWaivers` in
`modules/ci/policyrelease/builder.go` (bundle subject) and
`validateFinalReviewState` in `modules/ci/policyrelease/release.go` (archive subject).
A review of the repository template cannot truthfully be copied into either
exact-artifact review field. Consequently unattended `make dev` cannot currently
complete a newly keyed installation without new independent artifact reviews.

## Bounded decision proposed

Permit a distinct **local development derivation** evidence path for the initial
bootstrap of a synthetic, non-distributed development installation only.
Independent architecture/contract-owner, QA, and security reviews bind the exact
template, compiler, dependency closure, and conformance-test revision once.
Each installer then proves the exact derivation and reruns the required tests.
Installer-generated receipts are explicitly build/test results, never independent
review approvals of the newly generated bundle or archive.

The implementation must enforce all of the following:

1. A closed, versioned template manifest binds the reviewed source/tree revision,
   compiler/toolchain and dependency digests, policy/model/schema bytes, test
   suite, required independent review records, and allowed substitution fields.
   Unknown fields, missing reviews, unreviewed/dirty inputs, and mismatched
   versions or digests deny. No floating branch, local environment override, or
   installer assertion can substitute for the reviewed template identity.
2. Substitutions are limited to generated instance IDs, instance-local public
   keys and their signed trust envelope, verified local OpenFGA store/model IDs,
   bounded issue/expiry times, and deterministic digests of those substitutions.
   Role semantics, policy rules, classification, disclosure mode, required
   contexts, trust purposes/thresholds, network restrictions, and evidence
   thresholds cannot be modified by this path.
3. The installer retains a machine-readable exact substitution map, source and
   output digests, actual conformance/mutation/dependency results, and offline
   verification result. The existing required policy-row and critical-mutation
   thresholds remain mandatory. Missing or failing results prevent signing and
   activation. Checked-in test fixtures and hard-coded PASS claims are forbidden.
4. A distinct, domain-separated signed local-derivation attestation binds the
   approved template/reviews, exact activation envelope and archive, generated
   trust identity, model read-back receipt, installer identity, and those actual
   results. Pre-signing and post-signing evidence remain acyclic. It must not be
   encoded as a production release attestation or as fabricated independent
   reviewer receipts. Closed schemas and runtime consumer checks validate it.
5. Use requires an explicit local-development bootstrap command, a new isolated
   instance/database, only synthetic data and disposable credentials, a visible
   development indicator, local HTTPS browser origin, and an explicitly reviewed
   private development service network. No production data, shared/customer
   deployment, externally exposed service, distributed release/image/installer,
   air-gap artifact, or existing production state is eligible. The local
   derivation artifacts and development keys are excluded from release outputs.
6. Runtime verification still checks exact archive structure and schemas, DSSE
   signatures, trust purpose and threshold, model read-back, native evaluator,
   activation pointer, independently retained monotonic anchor, policy time,
   fresh OpenFGA authorization, final revision fences, and audit/outbox atomicity.
   No unsigned mode, authorization bypass, reusable effect permit, cached allow,
   test-only authorizer, or silently reduced assurance mode is introduced.
7. Production and every nonlocal consumer reject the local evidence type and
   development trust keys. Restart may reverify the existing unexpired local
   activation; this path cannot renew, rotate, recover, upgrade, or promote it.
   Such operations retain their existing gates. Failed setup preserves evidence
   and denies protected requests; it must not automatically delete user data.

## Scope, alternatives, and acceptance

The only supersession is ADR-0006's exact independent bundle/archive review
granularity for the eligible initial local bootstrap. Production and release
review rules, cryptographic algorithms, custody requirements outside this scoped
development path, and Phase 1 release gates are unchanged. Relevant requirements:
`CLS-003`, `CLS-006`, `CLS-007`, `AUTH-006`, `SEC-006`, `TEST-008`, and `TEST-009`.

Retaining fresh independent reviews on every local install is safe but prevents
normal unattended developer setup. A shared static development key or unsigned
local mode is rejected. Reusing exact-artifact approval claims is rejected.

After owner approval, record this narrowly scoped decision through the ADR
process and implement its closed schemas and consumer tests in the single Phase
1 integration PR. Fresh independent QA and security must verify: exact reviewed
template binding; permitted substitutions only; real rerun receipts; rejection
of changed rules, missing/failed evidence, stale anchors, and nonlocal use; and
zero production-path behavioral changes. Approval of this proposal is not
approval of that implementation or the Phase 1 release.
