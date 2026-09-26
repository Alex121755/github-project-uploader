# Changelog

All notable changes are documented here. The project follows semantic versioning before the Codex development cache suffix.

## 0.3.0 - 2026-09-26

- Added a one-click, local credential self-check for selected projects, independent of GitHub authentication and upload plans.
- Reused the upload scanner to inspect selected files and reachable Git history, reporting credential locations without secret values.
- Expanded assignment detection to include prefixed names such as `OPENAI_API_KEY` and `AWS_SECRET_ACCESS_KEY`, plus quoted JSON keys.

## 0.2.0 - 2026-09-12

- Added selectable isolated projects for directories located inside larger Git repositories.
- Build exact snapshot trees and commits in temporary Git metadata without modifying or inheriting the parent repository.
- Added repeat uploads bound to immutable GitHub repository identity and the verified remote `main` OID.
- Added pending-state recovery, per-project execution locks, binding compare-and-swap checks, and remote-drift protection.
- Capture the immutable repository ID from GitHub's creation response, then verify identity and visibility immediately before and after push.
- Added regression coverage for parent isolation, first/repeat/no-op/empty-tree uploads, content-transform rejection, creation/push repository replacement, and interrupted-upload recovery.

## 0.1.1 - 2026-09-12

- Reworked the upload skill around direct, low-round-trip routes for picker, registered-project, and exact-path requests.
- Replaced duplicated JSON tool text with compact summaries while retaining complete structured results for Codex and the interactive UI.
- Added regression coverage for compact tool responses, expired plans, and exact public confirmation.

## 0.1.0 - 2026-09-12

Initial public release.

- Interactive MCP App for selecting registered projects.
- Local project registry and short-lived one-time upload plans.
- Current-file and bounded-history credential heuristics.
- Git state, configuration, remote, size, and repository-shape checks.
- Isolated exact-commit SSH push with remote OID verification.
- Private-by-default creation and explicit public-repository confirmation.
- Dependency-free Python MCP stdio server.
