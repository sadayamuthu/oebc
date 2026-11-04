# Contributing to OEBC

Thanks for helping. OEBC is only useful if its tiers can be trusted, so most
of this guide is about keeping the catalog correct: every change in behaviour
comes with a test that proves it, and coverage stays at 100%.

- [Ways to help](#ways-to-help)
- [Reporting a wrong or missing record](#reporting-a-wrong-or-missing-record)
- [Development setup](#development-setup)
- [Tests](#tests)
- [Code layout](#code-layout)
- [Exposure tier rules](#exposure-tier-rules)
- [Schema versioning](#schema-versioning)
- [Upstream data](#upstream-data)
- [Pull requests](#pull-requests)
- [Security](#security)
- [License](#license)

## Ways to help

- **Report a wrong tier, a wrong EPSS or KEV join, or a missing CVE.** This
  is the most useful contribution. See the next section.
- **Use the catalog** and tell us what you found, in an issue. Real-world use
  guides what to fix next.
- **Pick up an issue** labelled
  [`good first issue`](https://github.com/sadayamuthu/oebc/labels/good%20first%20issue)
  or [`help wanted`](https://github.com/sadayamuthu/oebc/labels/help%20wanted).

For anything larger than a small fix, open an issue first so we can agree on
the approach before you write the code.

## Reporting a wrong or missing record

Please include:

1. The CVE ID.
2. Which catalog you looked at: `latest.json.gz` from openastra.org (with its
   `generated_at_utc`), a `baseline-YYYY-MM-DD` release asset, or a local
   `oebc generate` run (with `oebc --version` and the flags you used).
3. The record as it appears in the catalog, and what you expected instead.
4. Where the expected value comes from: the NVD CVE page, the EPSS score for
   that CVE on that date, or the CISA KEV entry.

EPSS scores change daily and NVD records are revised, so a value that differs
from today's source may have been right on the day the catalog was built.
Comparing against the source on the catalog's `generated_at_utc` date helps
tell a stale value from a wrong join.

## Development setup

You need **Python 3.11** or newer. CI tests 3.11, 3.12 and 3.13.

```sh
git clone https://github.com/sadayamuthu/oebc.git
cd oebc
python3 -m venv venv && . venv/bin/activate
make install-dev          # pip install -e ".[dev]" and pre-commit install
oebc --version
```

Before pushing, run what CI runs. `develop.yml` runs `make install-dev` and
then `make check` on each Python version:

```sh
make check                # make lint + make test-cov
```

`make lint` is `ruff check src/ tests/`. `make format` applies `ruff format`
and `ruff check --fix`. The pre-commit hooks run ruff and the test suite on
each commit.

`make generate` builds a full catalog from the live sources. It downloads
every CVE from NVD, which takes hours without an NVD API key; pass one with
`oebc generate --nvd_api_key ...` if you have one. You don't need to run it
for most changes.

## Tests

```sh
make test                 # pytest tests/ -v
make test-cov             # same, with --cov-fail-under=100
```

Coverage of 100% is enforced: `pyproject.toml` adds
`--cov=oebc --cov-fail-under=100` to every pytest run, so `make test` fails
on a coverage drop too. Use `# pragma: no cover` only for lines that can't run
under test, as `__init__.py` does for the uninstalled-package fallback.

The tests never call the real NVD, EPSS or KEV APIs or openastra.org. HTTP is
mocked with `unittest.mock`. Keep it that way: tests must pass offline.

| File | What it covers |
|------|----------------|
| `tests/test_generate.py` | Paging for NVD and EPSS, the KEV fetch, field extraction, tier and actionable rules, catalog assembly |
| `tests/test_fetch.py` | `oebc fetch`: download, gzip decompression, output path |
| `tests/test_cli.py` | Subcommand dispatch and flag passing |
| `tests/test_schema_validation.py` | Sample catalogs against `spec/schemas/oebc-v*.json` |
| `tests/test_version.py` | Package version is importable |

**Every behaviour change needs a test.** For a bug fix, add a test that fails
before your change and passes after it.

## Code layout

| Path | What it does |
|------|--------------|
| `src/oebc/cli.py` | CLI entry point: `oebc fetch`, `oebc generate`, `--version` |
| `src/oebc/fetch.py` | Downloads and decompresses the published catalog from openastra.org |
| `src/oebc/generate.py` | Fetches NVD, EPSS and KEV, joins them by CVE ID, computes `exposure_tier` and `actionable`, writes the JSON |
| `src/oebc/urls.py` | Default source URLs and the published catalog URL |
| `spec/VERSION` | Schema version (separate from the package version in `pyproject.toml`) |
| `spec/schemas/` | JSON Schema (Draft 2020-12) and its YAML copy |
| `.github/workflows/` | CI, daily catalog release, schema release, PyPI publish |

## Exposure tier rules

The rules live in `compute_exposure_tier()` and `compute_actionable()` in
`src/oebc/generate.py`. They are evaluated in order; the first match wins:

| Tier | Condition |
|------|-----------|
| `CRITICAL` | `kev_listed` is true |
| `HIGH` | `epss_score >= epss_high_threshold` (default 0.10) or `cvss_score >= 9.0` |
| `MEDIUM` | `epss_score >= epss_medium_threshold` (default 0.01) or `cvss_score >= 7.0` |
| `LOW` | everything else |

A null score never meets a threshold. The EPSS thresholds and
`actionable_min_tier` are CLI flags; the CVSS bands are fixed in the code.

Every published catalog records the rules it was built with in its `rules`
object, and consumers rely on them. A change to a rule or a default is
therefore a change to the data, not only to the code:

1. Open an issue first and explain why the rule should change.
2. Update `compute_exposure_tier()` and the `rules` text built in
   `build_catalog()` together, so the catalog describes itself correctly.
3. Update the parametrized cases in `tests/test_generate.py`.
4. Update the tier table in the README.

## Schema versioning

The schema version in `spec/VERSION` is separate from the package version in
`pyproject.toml`. The published paths use its `MAJOR.MINOR` part, for example
`v0.1` in `https://openastra.org/oebc/catalog/v0.1/latest.json.gz`.

- Any change to the shape of the output (a field added, removed, renamed or
  retyped) needs a matching change to `spec/schemas/oebc-v*.json` and its
  `.yaml` copy, and a test in `tests/test_schema_validation.py`.
- When `spec/` changes on `main`, `schema-release.yml` publishes the schema
  to openastra.org and tags `spec-v<VERSION>`. It fails if that tag already
  exists, so a change to `spec/` must bump `spec/VERSION`.
- A `MAJOR.MINOR` bump moves the catalog to a new path. Update
  `OEBC_CATALOG_URL` in `src/oebc/urls.py`, rename the schema files, and
  update the URLs in the README.

## Upstream data

OEBC republishes data from three sources. The MIT license covers the code in
this repository, not that data, which stays under its providers' terms:

- **NVD**, from the National Institute of Standards and Technology. See the
  [NVD terms of use](https://nvd.nist.gov/developers/terms-of-use). This
  product uses the NVD API but is not endorsed or certified by the NVD.
- **EPSS**, from [FIRST](https://www.first.org/epss/). See FIRST's EPSS
  pages for its usage and citation guidance.
- **Known Exploited Vulnerabilities catalog**, from
  [CISA](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).

Don't add a new data source without opening an issue first, and check its
terms allow redistribution.

## Pull requests

- Keep each PR to one change; small PRs get reviewed faster.
- Use the commit message style in the history: `type: summary`, for example
  `fix: gzip-compress catalog to stay under GitHub's 100 MB file limit`.
  Types in use: `feat`, `fix`, `docs`, `ci`, `chore`.
- `make check` must pass on Python 3.11, 3.12 and 3.13.
- Update README.md when you change behaviour a user can see: a flag, a
  field, a tier rule or a URL.
- Don't commit generated catalogs. `oebc_full_catalog_enriched.json` is in
  `.gitignore`; catalogs are built in CI and published to openastra.org.

## Security

Please don't report security problems in a public issue. Use
[**Report a vulnerability**](https://github.com/sadayamuthu/oebc/security/advisories/new)
on the repository's Security tab instead. See [SECURITY.md](SECURITY.md) for
what to include and what's in scope.

## License

OEBC is licensed under the [MIT License](LICENSE). By contributing, you agree
that your contributions are licensed under the same license.
