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

## Set up

There is no install step: the verifier has no runtime dependencies. You need Node.js 24 or later.
Run `npm test` from the clone. On a Node build without ML-DSA-65 (OpenSSL 3.5 or later), the hybrid
tests are skipped.

## Test vectors

`test/vectors/` holds records and trust files signed by Parmana's signing code, which lives in the
[parmana-core](https://github.com/pavancharak/parmana-core) repository. They are labelled test
material. You cannot regenerate them from this repository. To add a vector, open an issue
describing the case; it is generated in parmana-core and copied here with its trust file. For a
test that needs a key, generate one at run time, as `test/helpers.mjs` does.

## Examples

Each example is a file in `examples/` named with a two-digit number and `.mjs`, such as
`10-my-example.mjs`. `npm run examples` runs them in number order. Give a new example the next free
number. It must exit `0` when it behaves as described, because CI runs the set.

## Style

The repository has no linter or formatter configured. Follow the style of the code around your
change: ES modules, no new dependencies, and comments only where the reason is not obvious.

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
