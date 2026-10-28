# Evidence Integrity Policy

This project distinguishes **design artifacts** from **execution evidence**.

- Sample events are explicitly stored under `sample-data/` or labeled as samples.
- Files under `evidence/` must come from an actual lab execution.
- Sensitive identifiers must be redacted before publication.
- Results must not be edited to convert a failure into a pass.
- Failed controls should be documented as findings and remediated.

This prevents portfolio evidence from misleading reviewers.
