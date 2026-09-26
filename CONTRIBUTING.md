# Contributing

Contributions are welcome, especially focused tests and portability improvements.

## Ground rules

- Do not weaken a blocker merely to make a project pass preflight.
- Preserve private-by-default behavior and the second exact-name confirmation for public repositories.
- Never add force-push, mirror-push, automatic deletion, or silent `origin` replacement.
- Keep all subprocess calls argument-array based with `shell=False`.
- Treat project paths, Git metadata, command output, and remote URLs as untrusted data.
- Preserve isolated-subdirectory containment: never inherit parent Git state and never write Git metadata into the selected directory or its parent.
- Do not add live credentials or token-shaped literals to fixtures. Build synthetic values from separate string fragments at runtime.
- Add a regression test for every security-sensitive change.

## Development workflow

1. Fork and clone the repository.
2. Create a focused branch.
3. Make the smallest coherent change.
4. Run the full test suite and syntax/JSON checks documented in the README.
5. Explain local and remote side effects in the pull request.

Tests must not create real GitHub repositories or push to the network. Mock remote operations or use an isolated local bare repository.

## Pull-request checklist

- [ ] Existing tests pass with resource warnings treated as errors.
- [ ] New behavior has coverage, including failure behavior.
- [ ] No credential, private path, generated cache, or vendored runtime entered the diff.
- [ ] README/security documentation matches changed behavior.
- [ ] Tool annotations and confirmation boundaries remain accurate.
