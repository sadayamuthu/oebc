"""Tests for oebc.generate — all tests use fake fixtures, no live HTTP calls."""

from __future__ import annotations

import argparse
import json
from unittest.mock import MagicMock, patch

import pytest

from oebc.generate import (
    _generate_parser,
    build_catalog,
    compute_actionable,
    compute_exposure_tier,
    extract_cvss,
    extract_cwes,
    extract_description,
    fetch_epss_scores,
    fetch_kev,
    fetch_nvd_cves,
)
from oebc.generate import (
    main as generate_main,
)

# ─── Fake fixtures ──────────────────────────────────────────────────────────

def _nvd_page(cves, total, start=0):
    """Build a fake NVD API response page."""
    return {
        "totalResults": total,
        "resultsPerPage": len(cves),
        "startIndex": start,
        "vulnerabilities": [{"cve": c} for c in cves],
    }


def _nvd_cve(cve_id, cvss_score=7.5, cvss_version="3.1", description="A vulnerability.", cwes=None):
    """Build a minimal fake NVD CVE object."""
    metrics = {}
    if cvss_score is not None:
        key = "cvssMetricV31" if cvss_version == "3.1" else "cvssMetricV30"
        metrics[key] = [{
            "cvssData": {
                "version": cvss_version,
                "vectorString": f"CVSS:{cvss_version}/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "baseScore": cvss_score,
                "baseSeverity": "HIGH" if cvss_score < 9.0 else "CRITICAL",
            }
        }]
    weaknesses = []
    if cwes:
        weaknesses = [{"description": [{"lang": "en", "value": c} for c in cwes]}]
    return {
        "id": cve_id,
        "published": "2024-01-01T00:00:00.000",
        "lastModified": "2024-06-01T00:00:00.000",
        "descriptions": [{"lang": "en", "value": description}],
        "metrics": metrics,
        "weaknesses": weaknesses,
    }


def _epss_page(data, total, offset=0, limit=10000):
    return {"status": "OK", "total": total, "offset": offset, "limit": limit, "data": data}


def _epss_record(cve_id, score="0.12345", percentile="0.98765"):
    return {"cve": cve_id, "epss": score, "percentile": percentile, "date": "2026-03-16"}


def _kev_response(cves):
    return {
        "title": "CISA KEV",
        "catalogVersion": "2026.03.16",
        "count": len(cves),
        "vulnerabilities": cves,
    }


def _kev_entry(cve_id, date_added="2024-01-15", due_date="2024-02-05", ransomware="Known"):
    return {
        "cveID": cve_id,
        "vendorProject": "Apache",
        "product": "Log4j",
        "vulnerabilityName": "Test Vuln",
        "dateAdded": date_added,
        "shortDescription": "Test",
        "requiredAction": "Patch",
        "dueDate": due_date,
        "knownRansomwareCampaignUse": ransomware,
    }


# ─── fetch_nvd_cves ──────────────────────────────────────────────────────────

def test_fetch_nvd_cves_single_page():
    page = _nvd_page([_nvd_cve("CVE-2024-0001"), _nvd_cve("CVE-2024-0002")], total=2)
    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    mock_resp.json.return_value = page

    with patch("oebc.generate.requests.get", return_value=mock_resp) as mock_get:
        result = fetch_nvd_cves("https://nvd.example.com")

    assert len(result) == 2
    assert result[0]["id"] == "CVE-2024-0001"
    mock_get.assert_called_once()


def test_fetch_nvd_cves_multiple_pages():
    page1 = _nvd_page([_nvd_cve("CVE-2024-0001")], total=2, start=0)
    page1["resultsPerPage"] = 1
    page2 = _nvd_page([_nvd_cve("CVE-2024-0002")], total=2, start=1)
    page2["resultsPerPage"] = 1

    responses = [MagicMock(), MagicMock()]
    responses[0].raise_for_status.return_value = None
    responses[0].json.return_value = page1
    responses[1].raise_for_status.return_value = None
    responses[1].json.return_value = page2

    with patch("oebc.generate.requests.get", side_effect=responses):
        result = fetch_nvd_cves("https://nvd.example.com")

    assert len(result) == 2
    assert {r["id"] for r in result} == {"CVE-2024-0001", "CVE-2024-0002"}


def test_fetch_nvd_cves_empty_page_breaks():
    """When API reports total=5 but returns empty vulnerabilities list, break out."""
    page = {"totalResults": 5, "resultsPerPage": 0, "startIndex": 0, "vulnerabilities": []}
    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    mock_resp.json.return_value = page

    with patch("oebc.generate.requests.get", return_value=mock_resp):
        result = fetch_nvd_cves("https://nvd.example.com")

    assert result == []


# ─── fetch_epss_scores ───────────────────────────────────────────────────────

def test_fetch_epss_scores_single_page():
    page = _epss_page([_epss_record("CVE-2024-0001", "0.5", "0.9")], total=1)
    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    mock_resp.json.return_value = page

    with patch("oebc.generate.requests.get", return_value=mock_resp):
        result = fetch_epss_scores("https://epss.example.com")

    assert result["CVE-2024-0001"]["epss"] == pytest.approx(0.5)
    assert result["CVE-2024-0001"]["percentile"] == pytest.approx(0.9)


def test_fetch_epss_scores_multiple_pages():
    page1 = _epss_page([_epss_record("CVE-2024-0001")], total=2, offset=0, limit=1)
    page2 = _epss_page([_epss_record("CVE-2024-0002")], total=2, offset=1, limit=1)

    responses = [MagicMock(), MagicMock()]
    responses[0].raise_for_status.return_value = None
    responses[0].json.return_value = page1
    responses[1].raise_for_status.return_value = None
    responses[1].json.return_value = page2

    with patch("oebc.generate.requests.get", side_effect=responses):
        result = fetch_epss_scores("https://epss.example.com")

    assert "CVE-2024-0001" in result
    assert "CVE-2024-0002" in result


def test_fetch_epss_scores_empty_page_breaks():
    """When API reports total=5 but returns empty data list, break out."""
    page = _epss_page([], total=5, offset=0)
    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    mock_resp.json.return_value = page

    with patch("oebc.generate.requests.get", return_value=mock_resp):
        result = fetch_epss_scores("https://epss.example.com")

    assert result == {}


# ─── fetch_kev ───────────────────────────────────────────────────────────────

def test_fetch_kev():
    payload = _kev_response([
        _kev_entry("CVE-2021-44228", "2021-12-10", "2021-12-24", "Known"),
        _kev_entry("CVE-2022-0001", "2022-01-01", "2022-01-15", "Unknown"),
    ])
    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    mock_resp.json.return_value = payload

    with patch("oebc.generate.requests.get", return_value=mock_resp):
        result = fetch_kev("https://kev.example.com")

    assert result["CVE-2021-44228"]["date_added"] == "2021-12-10"
    assert result["CVE-2021-44228"]["due_date"] == "2021-12-24"
    assert result["CVE-2021-44228"]["ransomware_use"] == "Known"
    assert result["CVE-2022-0001"]["ransomware_use"] == "Unknown"


# ─── extract_cvss ────────────────────────────────────────────────────────────

def test_extract_cvss_v31():
    cve = _nvd_cve("CVE-2024-0001", cvss_score=7.5, cvss_version="3.1")
    score, vector, version, severity = extract_cvss(cve)
    assert score == pytest.approx(7.5)
    assert "CVSS:3.1" in vector
    assert version == "3.1"
    assert severity == "HIGH"


def test_extract_cvss_v30_fallback():
    cve = _nvd_cve("CVE-2024-0001", cvss_score=8.0, cvss_version="3.0")
    score, _vector, version, _severity = extract_cvss(cve)
    assert score == pytest.approx(8.0)
    assert version == "3.0"


def test_extract_cvss_null_when_no_metrics():
    cve = _nvd_cve("CVE-2024-0001", cvss_score=None)
    score, vector, version, severity = extract_cvss(cve)
    assert score is None
    assert vector is None
    assert version is None
    assert severity is None


# ─── extract_cwes ────────────────────────────────────────────────────────────

def test_extract_cwes_with_values():
    cve = _nvd_cve("CVE-2024-0001", cwes=["CWE-79", "CWE-89"])
    assert extract_cwes(cve) == ["CWE-79", "CWE-89"]


def test_extract_cwes_empty():
    cve = _nvd_cve("CVE-2024-0001", cwes=None)
    assert extract_cwes(cve) == []


def test_extract_cwes_skips_noinfo():
    """NVD uses 'NVD-CWE-noinfo' and 'NVD-CWE-Other' as placeholder values — exclude them."""
    cve = _nvd_cve("CVE-2024-0001", cwes=["NVD-CWE-noinfo", "CWE-79", "NVD-CWE-Other"])
    assert extract_cwes(cve) == ["CWE-79"]


# ─── extract_description ─────────────────────────────────────────────────────

def test_extract_description_english():
    cve = _nvd_cve("CVE-2024-0001", description="A serious vulnerability.")
    assert extract_description(cve) == "A serious vulnerability."


def test_extract_description_no_english_returns_empty():
    cve = {"id": "CVE-2024-0001", "descriptions": [{"lang": "es", "value": "Una vulnerabilidad."}],
           "metrics": {}, "weaknesses": [], "published": "2024-01-01T00:00:00.000",
           "lastModified": "2024-01-01T00:00:00.000"}
    assert extract_description(cve) == ""


# ─── compute_exposure_tier ───────────────────────────────────────────────────

@pytest.mark.parametrize("kev,epss,cvss,epss_high,epss_med,expected", [
    # KEV wins unconditionally
    (True, 0.0, 1.0, 0.10, 0.01, "CRITICAL"),
    (True, None, None, 0.10, 0.01, "CRITICAL"),
    # HIGH via EPSS threshold
    (False, 0.10, 5.0, 0.10, 0.01, "HIGH"),
    (False, 0.50, 5.0, 0.10, 0.01, "HIGH"),
    # HIGH via CVSS >= 9.0
    (False, 0.0, 9.0, 0.10, 0.01, "HIGH"),
    (False, None, 9.5, 0.10, 0.01, "HIGH"),
    # MEDIUM via EPSS threshold
    (False, 0.01, 5.0, 0.10, 0.01, "MEDIUM"),
    (False, 0.05, 5.0, 0.10, 0.01, "MEDIUM"),
    # MEDIUM via CVSS >= 7.0
    (False, 0.0, 7.0, 0.10, 0.01, "MEDIUM"),
    (False, None, 8.9, 0.10, 0.01, "MEDIUM"),
    # LOW — nothing qualifies
    (False, 0.0, 5.0, 0.10, 0.01, "LOW"),
    (False, None, None, 0.10, 0.01, "LOW"),
    (False, None, 6.9, 0.10, 0.01, "LOW"),
    # Null EPSS doesn't qualify EPSS thresholds
    (False, None, 0.0, 0.10, 0.01, "LOW"),
])
def test_compute_exposure_tier(kev, epss, cvss, epss_high, epss_med, expected):
    assert compute_exposure_tier(kev, epss, cvss, epss_high, epss_med) == expected


# ─── compute_actionable ──────────────────────────────────────────────────────

@pytest.mark.parametrize("tier,min_tier,expected", [
    ("LOW", "medium", False),
    ("MEDIUM", "medium", True),
    ("HIGH", "medium", True),
    ("CRITICAL", "medium", True),
    ("LOW", "high", False),
    ("MEDIUM", "high", False),
    ("HIGH", "high", True),
    ("CRITICAL", "high", True),
    ("LOW", "low", True),
    ("CRITICAL", "critical", True),
    ("HIGH", "critical", False),
])
def test_compute_actionable(tier, min_tier, expected):
    assert compute_actionable(tier, min_tier) == expected


# ─── build_catalog ───────────────────────────────────────────────────────────

def _default_args(**kwargs):
    defaults = dict(
        out="out.json",
        actionable_min_tier="medium",
        epss_high_threshold=0.10,
        epss_medium_threshold=0.01,
        nvd_url="https://nvd.example.com",
        epss_url="https://epss.example.com",
        kev_url="https://kev.example.com",
    )
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


def test_build_catalog_enriches_kev_cve():
    nvd = [_nvd_cve("CVE-2021-44228", cvss_score=10.0)]
    epss = {"CVE-2021-44228": {"epss": 0.975, "percentile": 0.999}}
    kev = {"CVE-2021-44228": {"date_added": "2021-12-10", "due_date": "2021-12-24", "ransomware_use": "Known"}}

    catalog = build_catalog(nvd, epss, kev, _default_args())

    assert catalog["count"] == 1
    v = catalog["vulnerabilities"][0]
    assert v["cve_id"] == "CVE-2021-44228"
    assert v["kev_listed"] is True
    assert v["kev_date_added"] == "2021-12-10"
    assert v["exposure_tier"] == "CRITICAL"
    assert v["actionable"] is True
    assert v["epss_score"] == pytest.approx(0.975)


def test_build_catalog_null_epss_and_kev():
    nvd = [_nvd_cve("CVE-2024-9999", cvss_score=5.0)]
    epss = {}
    kev = {}

    catalog = build_catalog(nvd, epss, kev, _default_args())

    v = catalog["vulnerabilities"][0]
    assert v["kev_listed"] is False
    assert v["kev_date_added"] is None
    assert v["epss_score"] is None
    assert v["epss_percentile"] is None
    assert v["exposure_tier"] == "LOW"
    assert v["actionable"] is False


def test_build_catalog_metadata():
    catalog = build_catalog([], {}, {}, _default_args())
    assert catalog["project"] == "Open Exposure Baseline Catalog (OEBC)"
    assert "generated_at_utc" in catalog
    assert "rules" in catalog
    assert catalog["rules"]["actionable_min_tier"] == "medium"
    assert catalog["count"] == 0


def test_build_catalog_rules_embedded():
    catalog = build_catalog([], {}, {}, _default_args(epss_high_threshold=0.20, epss_medium_threshold=0.05))
    rules = catalog["rules"]["exposure_tier_definition"]
    assert "0.2" in rules["high"]
    assert "0.05" in rules["medium"]


# ─── generate_main (end-to-end) ──────────────────────────────────────────────

def test_generate_main_writes_file(tmp_path):
    out = str(tmp_path / "catalog.json")
    args = _default_args(out=out)

    nvd_page = _nvd_page([_nvd_cve("CVE-2024-0001", cvss_score=10.0)], total=1)
    epss_page = _epss_page([_epss_record("CVE-2024-0001", "0.9", "0.99")], total=1)
    kev_payload = _kev_response([_kev_entry("CVE-2024-0001")])

    nvd_resp = MagicMock(raise_for_status=MagicMock(), json=MagicMock(return_value=nvd_page))
    epss_resp = MagicMock(raise_for_status=MagicMock(), json=MagicMock(return_value=epss_page))
    kev_resp = MagicMock(raise_for_status=MagicMock(), json=MagicMock(return_value=kev_payload))

    with patch("oebc.generate.requests.get", side_effect=[nvd_resp, epss_resp, kev_resp]):
        generate_main(args)

    with open(out, encoding="utf-8") as f:
        data = json.load(f)
    assert data["count"] == 1
    assert data["vulnerabilities"][0]["exposure_tier"] == "CRITICAL"


# ─── _generate_parser ────────────────────────────────────────────────────────

def test_generate_parser_defaults():
    parser = _generate_parser()
    args = parser.parse_args([])
    assert args.out == "oebc_full_catalog_enriched.json"
    assert args.actionable_min_tier == "medium"
    assert args.epss_high_threshold == pytest.approx(0.10)
    assert args.epss_medium_threshold == pytest.approx(0.01)


def test_generate_parser_overrides():
    parser = _generate_parser()
    args = parser.parse_args([
        "--out", "my.json",
        "--actionable_min_tier", "high",
        "--epss_high_threshold", "0.25",
        "--epss_medium_threshold", "0.05",
    ])
    assert args.out == "my.json"
    assert args.actionable_min_tier == "high"
    assert args.epss_high_threshold == pytest.approx(0.25)
