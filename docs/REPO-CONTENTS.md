# What this repository contains

This is the public repository for `parmana-verifier`, licensed under Apache-2.0. It holds only the offline verifier and what people need to use, test, and contribute to it.

## Should contain

- `src/`, `bin/`: the verifier and its command-line wrapper.
- `test/`, including `test/vectors/` (test records and keys, each labelled as test material).
- `examples/`: runnable examples.
- `docs/SECURITY-REVIEW.md`: the scope document for external reviewers.
- `README.md`, `LICENSE`, `NOTICE`, `CHANGELOG.md`, `CONTRIBUTING.md`, `SECURITY.md`, `package.json`.
- `.github/`: CI workflow and the pull request template.
- `.gitignore`, and this file.

## Must not contain

- Code or documents from the private `parmana-core` repository, including the product, policies, and connectors.
- Patent, claims, regulation-mapping, or decision documents.
- Working notes such as `REMAINING-WORK.md`, `DECISIONS.md`, or draft agreements.
- `.env` files, private keys, tokens, database URLs, or production records.

## Before every update

1. Run `git status` and review every new file with `git diff --stat`.
2. Run `npm test` and `npm run examples` on Node 24 or newer.
3. Search the changes for core-specific names and for anything in the "must not" list.
4. Confirm the repository is still public on GitHub.
