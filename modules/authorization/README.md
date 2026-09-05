# modules/authorization

The WS-06 central boundary now implements the initial local User metadata slice:

- fresh repository-backed authentication (in `modules/identity`), explicit
  instance/Organization/Team/Project relations, and stock OpenFGA HTTP checks;
- exact immutable model selection, `HIGHER_CONSISTENCY`, no decision cache or
  retries, direct tuple write/read-back receipts, and fail-closed pending grants;
- native signed-profile sensitivity evaluation and complete server-derived OWGP
  security presentation; unsupported restriction/context/effect paths deny;
- sealed two-second decisions carrying the complete activation and security
  revision vector, with network-free final comparison inside the root transaction;
- bounded DSSE/P-256 verification of trust, activation and release signatures,
  complete archive/content validation reused from the policy-release producer,
  and an independently retained Linux local-development policy-time anchor.

`Decision.WithContext` carries at most two decisions: the primary create/read
decision and, when applicable, the parent-Team hierarchy or owning-Team read
decision. The PostgreSQL adapter must require the exact expected actions/targets,
lock and load every canonical fence, compare-max the host anchor, validate every
decision, and atomically persist domain changes and audit/outbox evidence. A
decision or tuple receipt is not a provider effect permit. Browser response
release still requires the root request-boundary adapter and presentation rules.

The pinned model successor is `policies/openfga/model-v0.2.fga`. Its versioned
JSON canonicalizer removes only stock protobuf empty defaults before exact
read-back comparison. Team `lead` is direct User-only; parent hierarchy and
Project owning/contributing Teams grant no access. Actual Team creation/last-lead
and active-User invariants belong to the registered domain transaction.

Verification currently includes local identity revocation/negative contexts,
fresh HTTP calls, ambiguity/redirect rejection, all 16 final-fence components,
real P-256 thresholds/custody/expiry, host-anchor rollback defenses, and existing
policy-release archive/branch gates. `TestLiveOpenFGALocalProtocol`, supplied only
an explicitly isolated service URL and private token file, passed against stock
OpenFGA 1.19.0 backed by PostgreSQL: exact model, direct grants, idempotency,
Team roles, noninheritance, and non-User-lead denial (30 actual HTTP calls).

This is not complete P1-006 or an activated product path. Full valid signed
runtime activation and the truthful local bootstrap evidence producer remain
gated on the proposed local-development derivation decision. No test fixture,
invented review receipt, unsigned local mode, production bootstrap, strict mode,
Agent execution, trust rotation/recovery, or future restricted-label behavior is
enabled by these interfaces. The only accepted activation constructor currently
requires the existing exact-artifact review/attestation path.
