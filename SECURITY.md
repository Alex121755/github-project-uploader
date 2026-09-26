# Security Policy

GitHub Project Uploader performs security-sensitive local Git and remote repository operations. Please report suspected vulnerabilities privately.

## Supported version

Security fixes are applied to the latest commit on `main`. Pre-1.0 releases may change behavior while preserving the explicit-confirmation and no-force-push guarantees.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting feature for this repository when available. Do not include live credentials, private repository contents, personal file paths, or exploit data in a public issue.

Include:

- The affected commit or plugin version.
- The operating system, Python, Git, GitHub CLI, and Codex versions.
- A minimal reproduction built from synthetic data.
- The expected and observed safety boundary.
- Whether any local or remote state changed.

If private reporting is unavailable, open a public issue that contains no exploit details and ask the maintainer for a private contact channel.

## Security scope

High-priority reports include:

- A push that can reach a repository/ref other than the exact preflight target.
- A force, mirror, tag, or unrelated-branch push.
- A successful result before remote object-ID verification.
- Bypassing public-repository confirmation or reusing/altering a one-time plan.
- Secret values returned to the model/UI or written into plugin state.
- Execution of project-controlled Git filters, hooks, helpers, or transport rewrites during preflight or push.
- A race that changes the reviewed commit or selected content before upload.
- An isolated-subdirectory upload that reads parent-repository content/history or modifies the parent repository, its index/config/remotes, or the selected directory's Git metadata.
- Bypassing the isolated binding to adopt a same-name repository with a different immutable GitHub repository ID or remote `main` OID.

Heuristic false negatives in secret detection are valuable reports, but the scanner is defense in depth and cannot guarantee that all sensitive data is found.
