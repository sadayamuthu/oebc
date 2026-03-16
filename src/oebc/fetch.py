"""Download the pre-built OEBC catalog from openastra.org."""

from __future__ import annotations

import argparse
import gzip
import json

import requests

from .urls import OEBC_CATALOG_URL


def main(args: argparse.Namespace) -> None:
    print(f"Fetching catalog from {OEBC_CATALOG_URL} ...")
    r = requests.get(OEBC_CATALOG_URL, timeout=60)
    r.raise_for_status()
    # Catalog is gzip-compressed. Decompress regardless of Content-Encoding header
    # (GitHub Pages does not automatically set Content-Encoding for .gz files).
    raw = gzip.decompress(r.content)
    data = json.loads(raw)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"Wrote {data.get('count', '?')} vulnerabilities to {args.out}")
