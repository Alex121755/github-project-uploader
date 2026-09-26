# Security model

GitHub Project Uploader is designed to fail closed when it cannot prove that the reviewed local Git state and the requested remote target match the eventual push. It reduces common publication mistakes; it is not a security scanner or policy engine.

## Trust boundaries

- **Project content is untrusted.** Filenames, file bytes, refs, commits, Git configuration, attributes, ignore rules, hooks, filters, and remote URLs may be hostile.
- **A parent Git repository is outside an isolated selection.** Its files, history, index, configuration, remotes, attributes, and ignore rules are not part of the upload and must not influence it.
- **Local executable configuration is untrusted.** Git commands run with global/system configuration disabled and project execution paths constrained. Unsafe repository/worktree configuration blocks the operation.
- **GitHub CLI owns API authentication.** The plugin invokes `gh`; it never asks for or stores a GitHub token.
- **SSH owns Git authentication.** Pushes use a fixed `/usr/bin/ssh` command that disables user configuration, forwarding, proxy commands, and local commands.
- **Codex is the confirmation surface.** A private upload requires confirmation of a one-time plan. A public upload additionally requires the full target repository string.

## Snapshot binding

The standalone self-check runs the same bounded local scan over the intended upload scope, including reachable history of a selected Git repository. It requires neither GitHub authentication nor a target repository and creates no upload plan. It does not authorize an upload; preflight scans again when the user later requests one. Reports contain finding rules and file locations, never matched credential values.

Preflight creates a short-lived plan that binds the target owner/name/visibility and upload mode to a fingerprint of selected file content/modes, Git metadata, branch, and commit. Execution recomputes the snapshot and stops if it differs. New repositories receive one root commit only after a second snapshot confirms that no concurrent Git history appeared.

Existing repositories must be clean. The index tree must match `HEAD`, and canonical worktree hashes/modes must match the index. Hidden `assume-unchanged` and `skip-worktree` entries block upload.

For an isolated subdirectory, preflight builds a canonical Git tree in temporary metadata and stores its exact tree OID in the plan. Execution independently rebuilds that tree and requires the OID to match before any remote write. The temporary index starts empty, so removed or newly ignored files are absent from the next snapshot. Content transformations from selected-tree Git attributes are conservatively rejected when the staged blob would differ from the bytes that were scanned.

## Isolated-subdirectory binding

A registered directory without its own Git metadata below a larger Git repository is fixed as `isolated_subdirectory`. The uploader never writes Git metadata, an index, configuration, remotes, or commits into the selected directory or its parent repository. It uses the selection as an explicit work tree while `add` and commit construction operate through a temporary Git directory and index. Only `.gitignore` and `.gitattributes` files inside the selected directory apply.

When execution begins, local owner-only state first binds the selection to the target slug, visibility, `main`, and pending commit. Repository creation uses the GitHub API response to capture the immutable repository ID from the same operation, then requires a live lookup to return that ID before push. After a verified push it records the last commit OID. A later preflight requires the live repository and remote ref to match. Updates are full snapshots with that verified OID as their only parent and use an ordinary non-force push. Per-project execution locks and compare-and-swap state updates prevent two local plans from interleaving. A pending commit record allows recovery when a push fails or lands before final local bookkeeping completes.

## Transport isolation

The push is run from a temporary empty bare Git directory. Only the chosen source object database is exposed to that transport. Isolated subdirectories first construct their commit in a separate temporary object database. The destination is constructed as the exact SSH URL for the authenticated GitHub owner and validated repository name. The command pushes one exact object ID to one exact branch ref without force, mirror, tags, push options, hooks, or submodule recursion.

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

## Residual remote race and recovery boundary

Remote immutable identity, visibility, and `main` are checked during preflight and execution. Identity and visibility are checked immediately before and after push; the branch OID is checked immediately before and after push. A concurrent remote advance normally makes the non-force push fail. Git does not provide an expected-old-OID compare-and-swap without force-with-lease, which this project deliberately forbids. Therefore, if another actor deletes or rewinds `main` to an ancestor in the narrow interval between the final check and Git's push negotiation, the verified direct-child update can still be accepted as a fast-forward. The final OID is still verified, but the transient rewind cannot be detected afterward.

Git transport addresses a GitHub repository by owner/name, not immutable repository ID. If another actor deletes and recreates that exact slug in the very small interval after the final identity check and before the push reaches GitHub, Git may write the commit to the replacement repository. The post-push API identity check makes this a reported failure and leaves pending recovery state, but it cannot undo a write that already occurred. Do not rename, delete, recreate, or run another writer against the target repository during upload.

Repository creation and local binding are also not one atomic transaction. The uploader records pending state and the immutable repository ID before push whenever possible. A process failure after GitHub creates the repository but before its ID is recorded fails closed on retry rather than adopting the same-name repository automatically; that rare case requires manual review.

## Unsupported repository forms

The current release blocks Git LFS, submodules or additional repositories below the selected root, bare repositories, shallow clones, partial/promisor clones, detached HEAD, dirty repositories, replace refs/grafts, and executable Git configuration. A repository rooted at the exact selection uses standard mode; a repository only above a non-repository selection is supported through isolated-subdirectory mode. These are conservative product boundaries rather than claims that the forms are inherently unsafe.
