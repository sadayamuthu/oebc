"""Tests for catalog schema validation against spec/schemas/oebc-v0.1.json."""

from __future__ import annotations

import json
import pathlib

import jsonschema
import pytest


def _load_schema() -> dict:
    """Load the current schema file from spec/schemas/ (anchored to repo root)."""
    repo_root = pathlib.Path(__file__).parent.parent
    schema_files = list(repo_root.glob("spec/schemas/oebc-v*.json"))
    assert schema_files, f"No schema file found in {repo_root / 'spec/schemas/'}"
    with open(schema_files[0], encoding="utf-8") as f:
        return json.load(f)


def _minimal_vulnerability() -> dict:
    return {
        "cve_id": "CVE-2024-0001",
        "description": "A test vulnerability.",
        "published_date": "2024-01-01",
        "last_modified_date": "2024-06-01",
        "cwe_ids": [],
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss_version": "3.1",
        "cvss_severity": "HIGH",
        "epss_score": 0.05,
        "epss_percentile": 0.80,
        "kev_listed": False,
        "kev_date_added": None,
        "kev_due_date": None,
        "kev_ransomware_use": None,
        "exposure_tier": "MEDIUM",
        "actionable": True,
    }


def _minimal_catalog(vulnerabilities=None) -> dict:
    return {
        "project": "Open Exposure Baseline Catalog (OEBC)",
        "project_version": "0.1.0",
        "generated_at_utc": "2026-03-16T06:00:00Z",
        "sources": {
            "nvd": "https://services.nvd.nist.gov/rest/json/cves/2.0",
            "epss": "https://api.first.org/data/v1/epss",
            "kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        },
        "rules": {
            "exposure_tier_definition": {
                "critical": "kev_listed = true",
                "high": "epss_score >= 0.10 OR cvss_score >= 9.0",
                "medium": "epss_score >= 0.01 OR cvss_score >= 7.0",
                "low": "everything else",
            },
            "tier_order": "LOW < MEDIUM < HIGH < CRITICAL",
            "actionable_min_tier": "medium",
        },
        "count": len(vulnerabilities or []),
        "vulnerabilities": vulnerabilities or [],
    }


def test_valid_empty_catalog():
    schema = _load_schema()
    jsonschema.validate(_minimal_catalog(), schema)


def test_valid_catalog_with_vulnerability():
    schema = _load_schema()
    jsonschema.validate(_minimal_catalog([_minimal_vulnerability()]), schema)


def test_valid_catalog_with_null_fields():
    schema = _load_schema()
    vuln = _minimal_vulnerability()
    vuln["cvss_score"] = None
    vuln["cvss_vector"] = None
    vuln["cvss_version"] = None
    vuln["cvss_severity"] = None
    vuln["epss_score"] = None
    vuln["epss_percentile"] = None
    jsonschema.validate(_minimal_catalog([vuln]), schema)


def test_missing_required_top_level_field_fails():
    schema = _load_schema()
    catalog = _minimal_catalog()
    del catalog["project"]
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(catalog, schema)


def test_missing_required_vulnerability_field_fails():
    schema = _load_schema()
    vuln = _minimal_vulnerability()
    del vuln["exposure_tier"]
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(_minimal_catalog([vuln]), schema)


def test_invalid_exposure_tier_fails():
    schema = _load_schema()
    vuln = _minimal_vulnerability()
    vuln["exposure_tier"] = "EXTREME"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(_minimal_catalog([vuln]), schema)


def test_extra_top_level_field_fails():
    schema = _load_schema()
    catalog = _minimal_catalog()
    catalog["unexpected_field"] = "surprise"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(catalog, schema)
