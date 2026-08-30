# Artifact, package, and release model

Artifact/Package/Release are optional software-capability resources. Canonical records reference BlobStore objects and preserve Work/Commit/Build/Release provenance, OCI identity where applicable, checksum, SPDX SBOM, signature, and SLSA-compatible provenance. They never appear for a Project without the required active authorized capability.

Published artifacts are immutable. Corrections create a new version or explicit revocation. Provider migration preserves digests and canonical links; rollback selects the previous signed metadata/catalog without mutating historical provenance.
