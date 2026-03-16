"""Smoke test: verify the oebc package version is importable."""

from oebc import __version__


def test_version_is_string():
    assert isinstance(__version__, str)
    assert len(__version__) > 0
