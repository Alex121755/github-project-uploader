# Changelog

All notable changes are documented here. The project follows semantic versioning before the Codex development cache suffix.

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
