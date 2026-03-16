# Open Exposure Baseline Catalog (OEBC)

A daily, machine-readable CVE exposure baseline enriched with EPSS, KEV, and
derived exposure tiers. Built for CTEM platforms like ExposureGate.

## Install

```bash
pip install oebc
```

## Usage

```bash
# Download pre-built catalog (fast)
oebc fetch

# Generate from scratch (fetches NVD + EPSS + CISA KEV live)
oebc generate
```

## Catalog URL

- Latest: https://openastra.org/oebc/catalog/v0.1/latest.json
- Schema: https://openastra.org/oebc/schema/v0.1/oebc.json
