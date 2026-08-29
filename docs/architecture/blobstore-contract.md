# BlobStore contract

One provider-neutral interface supports filesystem, S3-compatible, Azure Blob, and GCS. Canonical Attachment/Artifact metadata holds stable ID, hash, size, media type, label, provenance, retention, malware state, and opaque object ID—never a provider locator. Upload/download/delete is server-authorized or uses short-lived scoped URLs. Objects, cache, temp, backup, and signed URLs are partitioned by Organization/security domain/container.

Provider migration is copy → hash/metadata verify → authorized cutover → reconcile, retaining the old protected copy through rollback. All providers pass one outage, URL-scope, partition, retention, scan, export/import, backup/restore, and migration suite.
