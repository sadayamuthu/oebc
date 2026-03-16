"""Download the pre-built OEBC catalog from openastra.org."""

from __future__ import annotations

import argparse
import json

import requests

from .urls import OEBC_CATALOG_URL


def main(args: argparse.Namespace) -> None:
    print(f"Fetching catalog from {OEBC_CATALOG_URL} ...")
    r = requests.get(OEBC_CATALOG_URL, timeout=30)
    r.raise_for_status()
    data = r.json()
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"Wrote {data.get('count', '?')} vulnerabilities to {args.out}")
