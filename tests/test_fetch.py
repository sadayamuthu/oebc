"""Tests for oebc.fetch — download pre-built catalog from openastra.org."""

from __future__ import annotations

import argparse
import gzip
import json
from unittest.mock import MagicMock, patch

import pytest

from oebc.fetch import main as fetch_main
from oebc.urls import OEBC_CATALOG_URL


def _make_args(out="oebc_full_catalog_enriched.json"):
    return argparse.Namespace(out=out)


def _fake_catalog():
    return {
        "project": "Open Exposure Baseline Catalog (OEBC)",
        "project_version": "0.1.0",
        "generated_at_utc": "2026-03-16T06:00:00Z",
        "count": 2,
        "vulnerabilities": [],
    }


def _gzip_json(data):
    return gzip.compress(json.dumps(data).encode())


def test_fetch_writes_default_output(tmp_path):
    out = str(tmp_path / "catalog.json")
    fake = _fake_catalog()
    mock_resp = MagicMock()
    mock_resp.content = _gzip_json(fake)
    mock_resp.raise_for_status.return_value = None

    with patch("oebc.fetch.requests.get", return_value=mock_resp) as mock_get:
        fetch_main(_make_args(out=out))

    mock_get.assert_called_once_with(OEBC_CATALOG_URL, timeout=60)
    with open(out, encoding="utf-8") as f:
        data = json.load(f)
    assert data["count"] == 2


def test_fetch_uses_custom_out(tmp_path):
    out = str(tmp_path / "my-catalog.json")
    mock_resp = MagicMock()
    mock_resp.content = _gzip_json(_fake_catalog())
    mock_resp.raise_for_status.return_value = None

    with patch("oebc.fetch.requests.get", return_value=mock_resp):
        fetch_main(_make_args(out=out))

    assert (tmp_path / "my-catalog.json").exists()


def test_fetch_raises_on_http_error():
    mock_resp = MagicMock()
    mock_resp.raise_for_status.side_effect = Exception("404 Not Found")

    with patch("oebc.fetch.requests.get", return_value=mock_resp), pytest.raises(
        Exception, match="404"
    ):
        fetch_main(_make_args())


def test_catalog_url_is_correct():
    assert OEBC_CATALOG_URL == "https://openastra.org/oebc/catalog/v0.1/latest.json.gz"
