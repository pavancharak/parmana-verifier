# Releasing parmana-verifier

The npm package is `@parmana/verifier`. The Python package is `parmana-verifier`. Both carry the same version. The version is `version` in `package.json`, and `version` in `python/pyproject.toml` and `__version__` in `python/parmana_verifier/__init__.py`. Change all three together.

## 1. Prepare

1. Bump the three version fields above.
2. Add a `CHANGELOG.md` entry for the new version.
3. Make sure CI is green on `main`.

## 2. Create a GitHub release

On GitHub, go to Releases, choose **Draft a new release**, create the tag `verifier-v<version>` targeting `main`, and publish it.

Publishing the release runs `.github/workflows/release.yml`. It runs the tests, builds the npm and Python packages, writes an SBOM for the npm package, attaches the files to the release, and attaches signed SLSA provenance (`multiple.intoto.jsonl`). Wait for the run to be green. The release should show the npm tarball, its `.cdx.json` SBOM, the Python wheel and source distribution, and the provenance.

## 3. Publish

Publishing to npm and PyPI is manual. Download the release's files and publish those exact files:

```bash
npm login
npm publish parmana-verifier-<version>.tgz --access public
```

```bash
python -m pip install --upgrade twine
python -m twine upload parmana_verifier-<version>-py3-none-any.whl parmana_verifier-<version>.tar.gz
```

Twine asks for a PyPI API token. Don't commit a token.

## 4. Check

Confirm the registries show the new version, for example with `npm view @parmana/verifier version`.
