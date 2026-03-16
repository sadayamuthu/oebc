"""Core catalog generation logic for OEBC.

Fetches CVE data from NVD, EPSS scores from FIRST.org, and KEV list from CISA.
Joins all three by CVE ID, computes exposure_tier and actionable, writes JSON.
"""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .urls import EPSS_URL, KEV_URL, NVD_URL

# NVD API returns at most 2000 results per page
_NVD_PAGE_SIZE = 2000

# EPSS API page size — fetch in large batches
_EPSS_PAGE_SIZE = 10000

# Tier ordering for actionable comparison
_TIER_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


# ─── Data fetching ───────────────────────────────────────────────────────────

def _make_session() -> requests.Session:
    """Return a requests Session with automatic retry on transient errors."""
    session = requests.Session()
    retry = Retry(
        total=5,
        backoff_factor=2,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def fetch_nvd_cves(nvd_url: str, api_key: str | None = None) -> list[dict]:
    """Fetch all CVEs from the NVD API (paginated). Returns list of raw CVE dicts."""
    cves: list[dict] = []
    start = 0
    total = None

    while total is None or start < total:
        params: dict = {"startIndex": start, "resultsPerPage": _NVD_PAGE_SIZE}
        if api_key:
            params["apiKey"] = api_key
        r = _make_session().get(
            nvd_url,
            params=params,
            timeout=60,
        )
        r.raise_for_status()
        data = r.json()
        total = data["totalResults"]
        page_cves = [v["cve"] for v in data.get("vulnerabilities", [])]
        cves.extend(page_cves)
        start += len(page_cves)
        if len(page_cves) == 0:
            break

    return cves


def fetch_epss_scores(epss_url: str) -> dict[str, dict]:
    """Fetch all EPSS scores (paginated). Returns dict keyed by CVE ID."""
    scores: dict[str, dict] = {}
    offset = 0
    total = None

    while total is None or offset < total:
        r = _make_session().get(
            epss_url,
            params={"offset": offset, "limit": _EPSS_PAGE_SIZE},
            timeout=60,
        )
        r.raise_for_status()
        data = r.json()
        total = data["total"]
        page_data = data.get("data", [])
        for record in page_data:
            scores[record["cve"]] = {
                "epss": float(record["epss"]),
                "percentile": float(record["percentile"]),
            }
        offset += len(page_data)
        if len(page_data) == 0:
            break

    return scores


def fetch_kev(kev_url: str) -> dict[str, dict]:
    """Fetch CISA KEV list. Returns dict keyed by CVE ID."""
    r = _make_session().get(kev_url, timeout=30)
    r.raise_for_status()
    data = r.json()
    return {
        v["cveID"]: {
            "date_added": v.get("dateAdded"),
            "due_date": v.get("dueDate"),
            "ransomware_use": v.get("knownRansomwareCampaignUse"),
        }
        for v in data.get("vulnerabilities", [])
    }


# ─── CVE field extraction ────────────────────────────────────────────────────

def extract_cvss(cve: dict) -> tuple[float | None, str | None, str | None, str | None]:
    """Extract (score, vector, version, severity) from a NVD CVE dict.

    Prefers CVSS v3.1, then v3.0. Returns (None, None, None, None) if no score assigned.
    """
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key, [])
        if entries:
            d = entries[0]["cvssData"]
            return (
                d.get("baseScore"),
                d.get("vectorString"),
                d.get("version"),
                d.get("baseSeverity"),
            )
    return None, None, None, None


def extract_cwes(cve: dict) -> list[str]:
    """Extract CWE IDs from a NVD CVE dict, excluding NVD placeholder values."""
    _PLACEHOLDERS = {"NVD-CWE-noinfo", "NVD-CWE-Other"}
    result = []
    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            val = desc.get("value", "")
            if desc.get("lang") == "en" and val not in _PLACEHOLDERS:
                result.append(val)
    return result


def extract_description(cve: dict) -> str:
    """Return the English description for a NVD CVE, or empty string if none."""
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            return desc.get("value", "")
    return ""


# ─── Enrichment ──────────────────────────────────────────────────────────────

def compute_exposure_tier(
    kev_listed: bool,
    epss_score: float | None,
    cvss_score: float | None,
    epss_high_threshold: float,
    epss_medium_threshold: float,
) -> str:
    """Compute exposure tier. Rules evaluated in priority order; first match wins.

    Tier ordering: LOW < MEDIUM < HIGH < CRITICAL
    Null scores do not qualify any threshold comparison.
    """
    if kev_listed:
        return "CRITICAL"
    epss_ok = epss_score is not None
    cvss_ok = cvss_score is not None
    if (epss_ok and epss_score >= epss_high_threshold) or (cvss_ok and cvss_score >= 9.0):
        return "HIGH"
    if (epss_ok and epss_score >= epss_medium_threshold) or (cvss_ok and cvss_score >= 7.0):
        return "MEDIUM"
    return "LOW"


def compute_actionable(exposure_tier: str, actionable_min_tier: str) -> bool:
    """Return True if exposure_tier >= actionable_min_tier (LOW < MEDIUM < HIGH < CRITICAL)."""
    return _TIER_ORDER[exposure_tier] >= _TIER_ORDER[actionable_min_tier.upper()]


# ─── Catalog assembly ────────────────────────────────────────────────────────

def build_catalog(
    nvd_cves: list[dict],
    epss_scores: dict[str, dict],
    kev_data: dict[str, dict],
    args: argparse.Namespace,
) -> dict[str, Any]:
    """Join NVD + EPSS + KEV, compute derived fields, return catalog dict."""
    vulnerabilities = []
    for cve in nvd_cves:
        cve_id = cve["id"]
        cvss_score, cvss_vector, cvss_version, cvss_severity = extract_cvss(cve)
        epss = epss_scores.get(cve_id)
        epss_score = epss["epss"] if epss else None
        epss_percentile = epss["percentile"] if epss else None
        kev = kev_data.get(cve_id)
        kev_listed = kev is not None
        exposure_tier = compute_exposure_tier(
            kev_listed, epss_score, cvss_score,
            args.epss_high_threshold, args.epss_medium_threshold,
        )
        vulnerabilities.append({
            "cve_id": cve_id,
            "description": extract_description(cve),
            "published_date": cve.get("published", "")[:10],
            "last_modified_date": cve.get("lastModified", "")[:10],
            "cwe_ids": extract_cwes(cve),
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "cvss_version": cvss_version,
            "cvss_severity": cvss_severity,
            "epss_score": epss_score,
            "epss_percentile": epss_percentile,
            "kev_listed": kev_listed,
            "kev_date_added": kev["date_added"] if kev else None,
            "kev_due_date": kev["due_date"] if kev else None,
            "kev_ransomware_use": kev["ransomware_use"] if kev else None,
            "exposure_tier": exposure_tier,
            "actionable": compute_actionable(exposure_tier, args.actionable_min_tier),
        })

    return {
        "project": "Open Exposure Baseline Catalog (OEBC)",
        "project_version": _package_version(),
        "generated_at_utc": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sources": {
            "nvd": args.nvd_url,
            "epss": args.epss_url,
            "kev": args.kev_url,
        },
        "rules": {
            "exposure_tier_definition": {
                "critical": "kev_listed = true",
                "high": f"epss_score >= {args.epss_high_threshold} OR cvss_score >= 9.0",
                "medium": f"epss_score >= {args.epss_medium_threshold} OR cvss_score >= 7.0",
                "low": "everything else",
            },
            "tier_order": "LOW < MEDIUM < HIGH < CRITICAL",
            "actionable_min_tier": args.actionable_min_tier,
        },
        "count": len(vulnerabilities),
        "vulnerabilities": vulnerabilities,
    }


def _package_version() -> str:
    from . import __version__
    return __version__


# ─── CLI entry point ─────────────────────────────────────────────────────────

def _generate_parser(add_help: bool = True) -> argparse.ArgumentParser:
    """Return the ArgumentParser for the generate subcommand."""
    p = argparse.ArgumentParser(
        prog="oebc generate",
        description="Generate the OEBC catalog from NVD, EPSS, and CISA KEV sources.",
        add_help=add_help,
    )
    p.add_argument("--out", default="oebc_full_catalog_enriched.json",
                   help="Output file path (default: oebc_full_catalog_enriched.json)")
    p.add_argument("--actionable_min_tier", default="medium",
                   choices=["low", "medium", "high", "critical"],
                   help="Minimum tier for actionable=true (default: medium)")
    p.add_argument("--epss_high_threshold", type=float, default=0.10,
                   help="EPSS score threshold for HIGH tier (default: 0.10)")
    p.add_argument("--epss_medium_threshold", type=float, default=0.01,
                   help="EPSS score threshold for MEDIUM tier (default: 0.01)")
    p.add_argument("--nvd_url", default=NVD_URL, help="Override NVD source URL")
    p.add_argument("--epss_url", default=EPSS_URL, help="Override EPSS source URL")
    p.add_argument("--kev_url", default=KEV_URL, help="Override CISA KEV source URL")
    p.add_argument("--nvd_api_key", default=None,
                   help="NVD API key for higher rate limits (optional)")
    return p


def main(args: argparse.Namespace) -> None:
    """Generate the catalog from live sources and write to args.out."""
    print(f"Fetching CVEs from NVD: {args.nvd_url}")
    nvd_cves = fetch_nvd_cves(args.nvd_url, api_key=getattr(args, "nvd_api_key", None))
    print(f"  → {len(nvd_cves)} CVEs fetched")

    print(f"Fetching EPSS scores: {args.epss_url}")
    epss_scores = fetch_epss_scores(args.epss_url)
    print(f"  → {len(epss_scores)} EPSS records fetched")

    print(f"Fetching CISA KEV: {args.kev_url}")
    kev_data = fetch_kev(args.kev_url)
    print(f"  → {len(kev_data)} KEV entries fetched")

    print("Building catalog...")
    catalog = build_catalog(nvd_cves, epss_scores, kev_data, args)

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(catalog, f, ensure_ascii=False, indent=2)
    print(f"Wrote {catalog['count']} vulnerabilities to {args.out}")
