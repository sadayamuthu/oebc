"""Default source URLs for OEBC data sources and published catalog.

Override any URL via CLI flags or by setting OEBC_*_URL environment variables.
"""

# NVD CVE 2.0 API — paginated, max 2000 results per page
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# FIRST.org EPSS API — exploitation probability scores for all CVEs
EPSS_URL = "https://api.first.org/data/v1/epss"

# CISA Known Exploited Vulnerabilities catalog
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Pre-built OEBC catalog published daily to openastra.org
# Update this constant when the schema major/minor version changes (e.g., v0.1 → v0.2)
OEBC_CATALOG_URL = "https://openastra.org/oebc/catalog/v0.1/latest.json"
