# Security Policy

## Reporting a vulnerability

Please don't report security problems in a public issue, pull request or
discussion. Use
[**Report a vulnerability**](https://github.com/sadayamuthu/oebc/security/advisories/new)
on the repository's Security tab instead. Only the maintainer can see the
report.

Include what you can of:

- the output of `oebc --version`, your Python version and your OS
- how OEBC was used: `oebc fetch`, `oebc generate` (with the flags you
  passed), the published catalog on openastra.org, or one of the
  repository's GitHub Actions workflows
- steps to reproduce, ideally a small input file or a script that serves one
- what happened and what you expected

You'll get a reply when the report has been read, and again when a fix is
ready. A code fix lands on `main`, and the next catalog build picks it up;
the advisory names you unless you'd rather it didn't.

## Supported versions

OEBC is pre-1.0. Fixes land on `main` and in the latest release only. Only
the current catalog at `https://openastra.org/oebc/catalog/v0.1/latest.json.gz`
is maintained; earlier `baseline-YYYY-MM-DD` snapshots are not rebuilt.

## What counts

OEBC downloads remote data and republishes it. `oebc generate` fetches the
NVD CVE API, the FIRST EPSS API and the CISA KEV feed, parses their JSON and
writes one file, the path given by `--out`. `oebc fetch` downloads the
published gzip catalog from openastra.org, decompresses it in memory and
writes it to `--out`. The daily workflow builds the catalog and pushes it to
the openastra.org site repository, where other tools consume it. Anything
that breaks one of these promises is a security issue:

- **Writing is limited to `--out`.** Input from a feed or from the published
  catalog that makes OEBC run a command, write any other file, or send data
  anywhere other than the configured source URLs is in scope.
- **Parsing is safe.** A feed response or catalog file that makes OEBC hang,
  or exhaust memory or disk far beyond what its contents justify (for
  example a gzip bomb passed to `oebc fetch`), is in scope.
- **Secrets stay secret.** A way for the NVD API key passed with
  `--nvd_api_key`, or the workflows' `OEBC_DEPLOY_TOKEN`, to end up in logs,
  in the catalog, in a release or with a third party is in scope.
- **The published data is what the pipeline built.** A way for someone other
  than the maintainer to change the catalog or schema published on
  openastra.org or attached to a GitHub Release, for example through a
  workflow injection, a dependency or a pull request, is in scope.

A wrong value, such as a CVE in the wrong tier or an EPSS score joined to the
wrong CVE, is a bug, not a vulnerability. Report it in a normal issue; see
[CONTRIBUTING.md](CONTRIBUTING.md). Errors in the upstream data itself belong
with its provider: NVD, FIRST or CISA.
