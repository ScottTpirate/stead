# OSCAL evidence boundary

Status: **Phase 0 approval candidate**
Requirements: `TEST-001`, `TEST-008`

This directory owns Stead's machine-readable security-control evidence exports. Phase 0 fixes the boundary only: control implementations and release evidence will be mapped into versioned OSCAL-compatible component definitions and assessment results without claiming certification, accreditation, FedRAMP authorization, or FIPS validation.

The release candidate must bind each exported result to the immutable source revision, artifact digest, test or scanner identity, execution time, policy/model/profile revisions, reviewer disposition, and waiver state. Protected test data, secrets, credentials, source paths, and unauthorized resource metadata are prohibited from evidence bundles.

`WS-13` is the sole editor. `WS-06` approves security semantics; independent QA and security validate the exact release manifest under `RG-08-SECURITY`. Later schema selection and control-catalog mapping require the relevant deferred ADR if they introduce a material compatibility choice.
