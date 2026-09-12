# Security model

GitHub Project Uploader is designed to fail closed when it cannot prove that the reviewed local Git state and the requested remote target match the eventual push. It reduces common publication mistakes; it is not a security scanner or policy engine.

## Trust boundaries

- **Project content is untrusted.** Filenames, file bytes, refs, commits, Git configuration, attributes, ignore rules, hooks, filters, and remote URLs may be hostile.
- **Local executable configuration is untrusted.** Git commands run with global/system configuration disabled and project execution paths constrained. Unsafe repository/worktree configuration blocks the operation.
- **GitHub CLI owns API authentication.** The plugin invokes `gh`; it never asks for or stores a GitHub token.
- **SSH owns Git authentication.** Pushes use a fixed `/usr/bin/ssh` command that disables user configuration, forwarding, proxy commands, and local commands.
- **Codex is the confirmation surface.** A private upload requires confirmation of a one-time plan. A public upload additionally requires the full target repository string.

## Snapshot binding

Preflight creates a short-lived plan that binds the target owner/name/visibility to a fingerprint of selected file content/modes, Git metadata, branch, and commit. Execution recomputes the snapshot and stops if it differs. New repositories receive one root commit only after a second snapshot confirms that no concurrent Git history appeared.

Existing repositories must be clean. The index tree must match `HEAD`, and canonical worktree hashes/modes must match the index. Hidden `assume-unchanged` and `skip-worktree` entries block upload.

## Transport isolation

The push is run from a temporary empty bare Git directory. Only the chosen source object database is exposed to that transport. The destination is constructed as the exact SSH URL for the authenticated GitHub owner and validated repository name. The command pushes one exact object ID to one exact branch ref without force, mirror, tags, push options, hooks, or submodule recursion.

After push, the plugin queries the exact remote branch and compares its case-sensitive ref name and object ID with the local target. A mismatch is a failure, never success.

## Scan budgets

| Check | Limit | Result when exceeded |
| --- | ---: | --- |
| Selected files | 50,000 | Block |
| Selected content | 2 GiB | Block |
| Current content scanned for signatures | 100 MiB | Block when complete inspection cannot be established |
| History path output | 32 MiB / 200,000 paths | Block |
| History object output | 64 MiB / 200,000 objects | Block |
| History content scan | 100 MiB total | Block when complete inspection cannot be established |
| Individual historical object scan | 50 MiB | Block |
| Attributes file | 1 MiB | Block |
| Selected file | 50 MiB warning; 100 MiB block | Warn/block |

## Known non-guarantees

The signature scanner is heuristic. Encoded, fragmented, encrypted, proprietary, newly introduced, or context-dependent secrets may not match. A clean preflight also does not establish the absence of personal information, copyrighted data, malicious code, vulnerable dependencies, unsafe build behavior, legal restrictions, branch protections, organization rules, or billing consequences.

Warnings require human judgment; zero warnings is not a certificate of safety. Review the exact repository content and Git history before making any repository public.

## Unsupported repository forms

The current release blocks Git LFS, submodules, nested repositories, bare repositories, shallow clones, partial/promisor clones, detached HEAD, dirty repositories, replace refs/grafts, and executable Git configuration. These are conservative product boundaries rather than claims that the forms are inherently unsafe.
