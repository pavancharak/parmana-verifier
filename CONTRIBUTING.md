# Contributing to parmana-verifier

Pull requests from outside Parmana Systems are welcome. For anything larger than a small fix,
open an issue first, so the design is agreed before the code is written. Questions, feedback and
bug reports are welcome as GitHub issues too.

## Sign off every commit

Every commit must carry a `Signed-off-by` line, certifying the
[Developer Certificate of Origin](https://developercertificate.org). The DCO is the statement
that you wrote the change, or have the right to submit it, and that it may be released under the
Apache License 2.0 that this project uses.

Add the line with `git commit -s`. A pull request with an unsigned commit fails the `DCO` check and
is not merged until the commit is signed off.

## Process

- Work on a branch from `main`, and open a pull request. Nothing is pushed to `main` directly.
- Add a test with each change. A bug fix adds a test that fails without it.
- Run `npm test` on Node 24 or later. CI runs the same tests and the examples.
- Update `CHANGELOG.md` and the documentation in `docs/` when behaviour a reader relies on changes.
- Do not submit confidential material, personal data, or code you have no right to license under
  Apache 2.0.

## Security issues

Report them privately, as described in [SECURITY.md](SECURITY.md), not in a public issue.

## Conduct

Everyone taking part follows the [Code of Conduct](CODE_OF_CONDUCT.md).
