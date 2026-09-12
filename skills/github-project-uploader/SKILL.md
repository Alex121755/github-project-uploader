---
name: github-project-uploader
description: Select a registered local project, run a safety preflight, and upload it to the user's authenticated GitHub account. Use when the user asks to choose, add, publish, push, or upload a local project to GitHub from Codex.
---

# GitHub Project Uploader

Use the plugin tools for a local project-to-GitHub workflow.

## Default flow

1. When the user wants to choose a project, call `render_upload_picker` so the interactive project card appears.
2. When the user names a precise local project path that is not registered, call `register_project` for that project root, then call `render_upload_picker`.
3. Before every upload, call `preflight_upload` with the chosen project ID and repository name. Use `visibility="private"` unless the user explicitly requests a public repository.
4. Do not call `execute_upload` from a vague request. Call it only after the user has explicitly confirmed the exact repository and visibility shown by the preflight result. A click on the clearly labelled upload button in the card is explicit confirmation for that one plan.
5. If the UI is unavailable, present the registered project names concisely in the conversation, obtain a specific selection, run preflight, show the target and issues, and wait for explicit confirmation before execution.

## Safety rules

- Treat each plan as one-time and short-lived. If it expires or the project changes, run preflight again.
- Never reveal matched secret values. Report only the rule, file path, and line number returned by the tool.
- Never bypass a blocking preflight issue, replace an existing `origin`, force-push, mirror-push, rewrite history, or delete a remote repository.
- Do not claim Git LFS support. The preflight blocks LFS attributes and pointer files because this plugin does not upload LFS objects.
- Do not bypass shallow/partial-history, worktree/index mismatch, executable Git configuration, or sensitive-path blockers. Ask the user to make the repository complete and clean, then preflight again.
- Public upload requires a new explicit request. Pass the exact `owner/repository` string as `confirm_public_repository` only after the user confirms it.
- If a registered path is missing or belongs to a larger Git repository, ask the user for the correct project root.
- Explain that a GitHub repository may be created even if a later network push fails; follow the tool's recovery guidance and re-run preflight.

## Helpful phrases

- “选择一个项目上传到 GitHub” → open the picker.
- “把这个项目加入列表” → register the current explicit project root, then open the picker.
- “上传为公开仓库” → preflight with `public`, show the warning, and require the exact second confirmation.
