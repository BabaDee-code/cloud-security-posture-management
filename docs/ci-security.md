# CI trust boundary

The CI workflow is part of the repository's software supply chain: code referenced by a workflow executes in a trusted GitHub Actions context and can influence test results and future delivery decisions.

## Controls

- **Least-privilege token:** workflow permissions remain `contents: read`.
- **Immutable action references:** third-party Actions are pinned to full commit SHAs rather than mutable major-version tags. Human-readable version comments preserve review context.
- **No persisted checkout credential:** `actions/checkout` uses `persist-credentials: false` because the test job does not need authenticated Git operations after checkout.
- **Bounded execution:** the test job has an explicit timeout to limit runaway execution and resource consumption.
- **Reviewable maintenance:** Dependabot watches the `github-actions` ecosystem so updates to pinned revisions arrive as normal pull requests with an auditable diff.

## Design decision

Pinning by SHA trades automatic tag movement for deterministic execution. This repository intentionally accepts that maintenance cost because CI dependencies cross a high-trust boundary. Dependabot provides the update mechanism so the pin does not become a reason to leave Actions stale.

This control does not make CI intrinsically trustworthy. Reviewers should still evaluate upstream action changes, workflow permissions, event triggers, and any use of secrets before merging workflow modifications.
