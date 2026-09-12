---
name: github-project-uploader
description: Select, register, preflight, and upload a local project to the user's authenticated GitHub account. Use for choosing, publishing, pushing, or uploading a local project to GitHub from Codex.
---

# GitHub Project Uploader

Use the plugin tools. For upload-only work, skip source inspection, web browsing, tests, and extra GitHub audits unless a tool fails or preparation was requested.

## Route

- Choose: call `render_upload_picker` once; it already includes project/auth data, so do not pair it with `list_projects`.
- Named registered project: reuse its latest ID, or call `list_projects` once and resolve one unambiguous match; skip the picker.
- Exact new root: call `register_project`; stop if only registration was requested, otherwise reuse its ID and suggested name; skip list/picker.
- Finish requested project edits first. Then call `preflight_upload` once, using the suggested name and `private` unless specified otherwise.
- Summarize only target, visibility, file count/size, blocker/warning counts, and actions; never echo raw results. If not ready, report blockers and stop—no confirmation or execution.
- If ready, require post-preflight confirmation of exact target and visibility. A labelled private-upload button counts. Public upload requires the full `owner/repository`; pass it as `confirm_public_repository`.
- Call `execute_upload` once. Report only URL, visibility, branch, and commit; do not relist, rerender, or re-preflight.

## Boundaries

- Plans are one-use and short-lived. Expiry or any project/account/target/visibility/finding change requires a new preflight and confirmation.
- Never expose matched secret values; show only returned rule, path, and line.
- Never bypass blockers, modify files merely to silence them, replace `origin`, force/mirror-push, rewrite history, delete remotes, or claim Git LFS support.
- Missing paths or larger-repository children require the exact root.
- A repository may remain after a push failure; report it and follow recovery guidance without auto-delete/rollback.
