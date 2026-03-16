"""Tests for oebc.cli — argument parsing and subcommand dispatch."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from oebc import __version__
from oebc.cli import main


def _run(argv):
    """Run CLI with given argv list."""
    with patch("sys.argv", ["oebc", *argv]):
        main()


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        _run(["--version"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert __version__ in out


def test_no_subcommand_exits():
    with pytest.raises(SystemExit):
        _run([])


def test_fetch_dispatches(tmp_path):
    out = str(tmp_path / "catalog.json")
    with patch("oebc.cli.fetch_main") as mock_fetch:
        _run(["fetch", "--out", out])
    mock_fetch.assert_called_once()
    args = mock_fetch.call_args[0][0]
    assert args.out == out


def test_fetch_default_out():
    with patch("oebc.cli.fetch_main") as mock_fetch:
        _run(["fetch"])
    args = mock_fetch.call_args[0][0]
    assert args.out == "oebc_full_catalog_enriched.json"


def test_generate_dispatches():
    with patch("oebc.cli.generate_main") as mock_gen:
        _run(["generate"])
    mock_gen.assert_called_once()


def test_generate_passes_flags():
    with patch("oebc.cli.generate_main") as mock_gen:
        _run(["generate",
              "--out", "my.json",
              "--actionable_min_tier", "high",
              "--epss_high_threshold", "0.20",
              "--epss_medium_threshold", "0.05"])
    args = mock_gen.call_args[0][0]
    assert args.out == "my.json"
    assert args.actionable_min_tier == "high"
    assert args.epss_high_threshold == pytest.approx(0.20)
    assert args.epss_medium_threshold == pytest.approx(0.05)


def test_generate_url_overrides():
    with patch("oebc.cli.generate_main") as mock_gen:
        _run(["generate",
              "--nvd_url", "https://custom-nvd.example.com",
              "--epss_url", "https://custom-epss.example.com",
              "--kev_url", "https://custom-kev.example.com"])
    args = mock_gen.call_args[0][0]
    assert args.nvd_url == "https://custom-nvd.example.com"
    assert args.epss_url == "https://custom-epss.example.com"
    assert args.kev_url == "https://custom-kev.example.com"
