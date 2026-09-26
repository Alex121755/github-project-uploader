---
name: github-project-uploader
description: Select, register, check for exposed credentials, preflight, and upload a local project to the user's GitHub account. Use for choosing, self-checking, publishing, pushing, or uploading a local project from Codex.
---

# GitHub Project Uploader

Use the plugin tools. For upload-only work, skip source inspection, web browsing, tests, and extra GitHub audits unless a tool fails or preparation was requested.

## Route

- Choose: call `render_upload_picker` once; it already includes project/auth data, so do not pair it with `list_projects`.
- Named registered project: reuse its latest ID, or call `list_projects` once and resolve one unambiguous match; skip the picker.
- Exact new directory: call `register_project`; stop if only registration was requested, otherwise reuse its ID and suggested name; skip list/picker. A directory without its own Git metadata inside a larger Git repository is intentionally registered as an isolated snapshot project.
- Self-check only: call `self_check_project` for the selected project. It scans the intended upload scope locally without a repository name, GitHub login, upload plan, or push. Report credential and other issue counts; show only rule, path, and line for actionable findings. Do not call upload preflight unless uploading was also requested.
- Finish requested project edits first. Then call `preflight_upload` once, using the suggested name and `private` unless specified otherwise.
- Summarize only target, visibility, upload mode when isolated, file count/size, blocker/warning counts, and actions; never echo raw results. If not ready, report blockers and stop—no confirmation or execution.
- If ready, require post-preflight confirmation of exact target and visibility. A labelled private-upload button counts. Public upload requires the full `owner/repository`; pass it as `confirm_public_repository`.
- Call `execute_upload` once. Report only URL, visibility, branch, and commit; do not relist, rerender, or re-preflight.

## Boundaries

- Plans are one-use and short-lived. Expiry or any project/account/target/visibility/finding change requires a new preflight and confirmation.
- If a tool reports an invalid plugin working directory or stale runtime after an update, stop. Start a new Codex task or restart Codex and then run a fresh preflight; never execute a plan from the stale process.
- Never expose matched secret values; show only returned rule, path, and line.
- A self-check with zero matches is a heuristic result, not proof that no credential exists. Upload still requires a fresh preflight and its confirmation.
- Never bypass blockers, modify files merely to silence them, replace `origin`, force/mirror-push, rewrite history, delete remotes, or claim Git LFS support.
- Missing or overly broad paths require a concrete project directory. For `isolated_subdirectory`, explain that only that directory is uploaded and the parent Git history/state is neither inherited nor modified.
- A Git repository rooted at the exact selected directory uses standard mode, even when another Git repository exists above it. Additional `.git` metadata, nested repositories, or submodules below the selected root remain blockers; isolated-subdirectory mode applies only when Git metadata exists above, not at, the selection.
- A repository may remain after a push failure; report it and follow recovery guidance without auto-delete/rollback.
