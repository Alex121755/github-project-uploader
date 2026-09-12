# GitHub Project Uploader

<p align="center">
  <img src="assets/logo.svg" width="96" alt="GitHub Project Uploader logo">
</p>

A safety-first Codex plugin for choosing a local project, running fail-closed checks, and pushing one exact commit to GitHub only after explicit confirmation.

[中文说明](README.zh-CN.md) · [Security model](docs/security-model.md) · [Report a vulnerability](SECURITY.md)

> [!IMPORTANT]
> This is an independent open-source project. It is not an official GitHub or OpenAI product and is not endorsed by either company.

## Why this exists

Publishing a local folder is easy to get wrong: ignored credentials may still exist in history, a dirty index can differ from the files you reviewed, a remote can be rewritten by Git configuration, and a successful-looking push can target the wrong ref. GitHub Project Uploader adds a deliberate review boundary between "this folder" and "make it a repository."

The plugin provides:

- An interactive project picker in supported Codex local-plugin surfaces.
- A local registry for adding exact project roots.
- A ten-minute, one-time preflight plan before every upload.
- Heuristic secret scanning across selected files and bounded Git history.
- Checks for Git state, hidden index flags, remote conflicts, oversized content, nested repositories, shallow/partial clones, and Git LFS.
- An isolated push of one exact commit, followed by verification of the remote branch object ID.
- Private repositories by default and a separate exact-name confirmation for public repositories.

## What it deliberately does not do

- It is not a backup or continuous-sync tool.
- It never force-pushes, mirror-pushes, deletes repositories, rewrites history, or silently replaces `origin`.
- It does not upload Git LFS objects, submodules, nested repositories, shallow clones, or partial clones.
- It does not prove that a project contains no secrets, personal information, malicious code, dependency vulnerabilities, licensing conflicts, or organization-policy violations.
- It does not automatically write a README or choose a license for projects you upload.

## Compatibility and prerequisites

- macOS or Linux. Windows is not currently supported.
- Python 3.10 or newer, available as `python3`.
- A modern Git installation.
- [GitHub CLI](https://cli.github.com/) available as `gh`.
- OpenSSH available at `/usr/bin/ssh`, with outbound access to `github.com:22`.
- A Codex surface that supports local plugins and MCP Apps. If the interactive card is unavailable, the same flow falls back to normal conversation.

The MCP server uses only the Python standard library; no `pip install` is required.

## Install from GitHub

Add this repository marketplace and install the plugin:

```bash
codex plugin marketplace add Alex121755/github-project-uploader --ref main
codex plugin add github-project-uploader@alex121755-tools
```

Start a new Codex task after installation so the plugin's skill and MCP tools are loaded.

To update later:

```bash
codex plugin marketplace upgrade alex121755-tools
codex plugin add github-project-uploader@alex121755-tools
```

To uninstall the plugin while keeping the marketplace configured:

```bash
codex plugin remove github-project-uploader@alex121755-tools
```

## Connect GitHub

The plugin uses GitHub CLI for account/repository API calls and SSH for Git pushes. Configure both:

```bash
gh auth login --git-protocol ssh
gh auth status
/usr/bin/ssh -F /dev/null -o BatchMode=yes -o ConnectTimeout=15 -T git@github.com
```

GitHub's SSH test prints a successful-authentication message but normally exits with a non-zero status because GitHub does not provide shell access.

The uploader intentionally ignores the user's SSH config during push, disables forwarding and proxy commands, and pins the connection to `github.com` on port 22. Environments that require a custom SSH proxy are therefore unsupported by this version.

Repositories are created only under the currently authenticated personal GitHub account. Selecting an organization as the owner is not supported in this release.

## Use it

In a new Codex task, say:

```text
Choose a project to upload to GitHub
```

or:

```text
选择一个项目上传到 GitHub
```

Then:

1. Choose a registered project, or register one exact project-root path.
2. Enter a GitHub repository name.
3. Run the preflight and review every blocker and warning.
4. For a private repository, confirm the one-time plan in the card.
5. For a public repository, return to the conversation and explicitly confirm the full `owner/repository` shown by preflight.

A plan expires after ten minutes and can be used only once. Any material project change requires a new preflight.

## What changes

| Situation | Local changes | GitHub changes |
| --- | --- | --- |
| Folder is not yet a Git repository | Initializes `main`, stages files allowed by `.gitignore`, creates one root commit named `Initial project upload`, and adds `origin` | Creates the requested repository and pushes that commit |
| Git repository with no commits yet | Stages files allowed by `.gitignore`, creates one root commit named `Initial project upload`, and adds `origin` when absent | Creates the target if absent, or verifies its visibility when a matching `origin` already points to it, then pushes that commit |
| Existing clean repository with at least one commit and no `origin` | Adds the exact GitHub SSH `origin`; does not create a new commit | Requires the target repository not to exist, then creates it and pushes current `HEAD` to the current branch |
| Existing clean repository with the matching `origin` | No history rewrite and no new commit | Creates the target if absent, or verifies its visibility if present, then pushes current `HEAD` to the current branch |
| A later step fails | Earlier local initialization, commit, or `origin` may remain | An empty repository may already exist |

The push includes the selected commit and its reachable ancestors. It does not push unrelated branches or tags. After pushing, the plugin reads the remote ref and requires its object ID to match exactly before reporting success.

The plugin never adopts an existing GitHub repository unless the local `origin` already matches the exact target.

The plugin does not automatically roll back partial work. Fix the reported authentication or network issue and run preflight again. Deleting a repository or undoing local Git initialization must remain a separate, explicit user action.

## Fail-closed checks

Preflight blocks or warns on conditions including:

- Likely credentials in selected file content, filenames, commit messages, the current branch name, and bounded history.
- Sensitive filenames such as environment files, private-key formats, credential stores, and service-account files.
- Dirty worktrees, index/worktree mismatches, `assume-unchanged`, and `skip-worktree` entries.
- Replace refs, grafts, executable Git filters, unsafe includes, URL rewrites, hooks, and transport overrides.
- Mismatched fetch/push URLs or a target repository with different visibility.
- Bare, nested, shallow, or partial repositories; submodules; and Git LFS attributes/pointers.
- More than 50,000 selected files or more than 2 GiB of selected content.
- Files at or above GitHub's practical size thresholds: 50 MiB warns and 100 MiB blocks.
- Scan inventories above 200,000 history objects or 200,000 historical paths.

Current-content and history scans are deliberately bounded to avoid unbounded memory and time use. Reaching a safety limit blocks the upload instead of silently skipping the check. See the [security model](docs/security-model.md) for exact budgets and non-guarantees.

## Privacy and local state

Selected files and Git history are scanned locally. Listing projects and preflight query GitHub for the active account and target repository metadata. Project content is transferred only during the confirmed push.

Codex receives project paths and redacted findings so it can explain blockers. Detected secret values are not intentionally returned. The plugin stores its private registry and one-time plans under:

```text
$CODEX_HOME/github-project-uploader/
```

State files use owner-only permissions and may contain project paths, target repository details, commit/branch metadata, and the last successful URL. They do not store project file contents or copy the GitHub token. Token storage remains the responsibility of GitHub CLI and the operating system.

## Troubleshooting

- **No picker card:** continue in conversation; the plugin can list projects and complete the same confirmation flow without UI.
- **GitHub account unavailable:** run `gh auth status`, then authenticate again with `gh auth login`.
- **SSH fails:** verify direct access with the SSH test command above. Custom `~/.ssh/config` settings are intentionally ignored.
- **Dirty repository:** commit, stash, or discard the changes yourself, then run a new preflight.
- **Wrong `origin`:** resolve it manually. The plugin will not replace it.
- **Shallow or partial clone:** fetch a complete local history before retrying.
- **Git LFS detected:** migrate the project away from LFS for this upload or use a separate LFS-aware workflow.
- **Plan expired/project changed:** run preflight again; old plans cannot be reused.
- **Repository created but push failed:** leave the repository in place, fix the reported problem, and preflight again. Cleanup is never automatic.

## Project layout

```text
.codex-plugin/plugin.json        Codex compatibility manifest
.mcp.json                        Local MCP server registration
.agents/plugins/marketplace.json Repository marketplace catalog
assets/uploader.html             Interactive MCP App
assets/logo.svg                  Original project icon
scripts/server.py                Dependency-free JSON-RPC/MCP stdio server
scripts/uploader_core.py         Preflight, Git, state, and transport logic
skills/.../SKILL.md              Agent workflow and confirmation rules
tests/                           Security and protocol regression tests
```

## Development

Run the complete local checks:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -W error::ResourceWarning -m unittest discover -s tests -v
python3 -m py_compile scripts/server.py scripts/uploader_core.py
python3 -m json.tool .codex-plugin/plugin.json >/dev/null
python3 -m json.tool .mcp.json >/dev/null
python3 -m json.tool .agents/plugins/marketplace.json >/dev/null
```

See [CONTRIBUTING.md](CONTRIBUTING.md) before changing upload semantics. Security-sensitive changes should include a regression test and preserve fail-closed behavior.

## License

MIT. See [LICENSE](LICENSE).
