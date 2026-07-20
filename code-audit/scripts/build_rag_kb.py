"""Build RAG knowledge base from NVD CVE and CISA KEV data.

Phase 1 (fast, ~30s):  CISA KEV — ~2,000 actively exploited CVEs
Phase 2 (slow, ~4-6h): NVD full history — ~250,000 CVEs since 1999

Usage:
    python scripts/build_rag_kb.py              # Phase 1 + 2
    python scripts/build_rag_kb.py --kev-only   # Phase 1 only
    python scripts/build_rag_kb.py --nvd-only   # Phase 2 only
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import hashlib
from pathlib import Path
from typing import Any

import requests

# Allow running from project root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.rag.vector_store import VectorStore
from src.utils.logger import setup_logger

logger = setup_logger()

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_PAGE_SIZE = 2000
NVD_DELAY = 0.7  # seconds between requests (50 req/30s with key = ~0.6s min)

# CWE → vulnerability type mapping (same as bigvul_loader)
CWE_TYPE_MAP = {
    "CWE-121": "buffer_overflow", "CWE-122": "buffer_overflow",
    "CWE-125": "out_of_bounds_read", "CWE-787": "out_of_bounds_write",
    "CWE-134": "format_string", "CWE-78": "command_injection",
    "CWE-77": "command_injection", "CWE-89": "sql_injection",
    "CWE-416": "use_after_free", "CWE-415": "double_free",
    "CWE-476": "null_pointer", "CWE-190": "integer_overflow",
    "CWE-20": "input_validation", "CWE-119": "buffer_overflow",
    "CWE-189": "integer_overflow", "CWE-200": "information_disclosure",
    "CWE-362": "race_condition", "CWE-399": "resource_exhaustion",
    "CWE-22": "path_traversal", "CWE-94": "code_injection",
    "CWE-502": "deserialization", "CWE-352": "csrf",
    "CWE-918": "ssrf", "CWE-79": "xss",
}


# =========================================================================
# CISA KEV downloader
# =========================================================================

def fetch_kev() -> list[dict]:
    """Download CISA Known Exploited Vulnerabilities catalog."""
    logger.info("Downloading CISA KEV catalog ...")
    resp = requests.get(KEV_URL, timeout=60)
    resp.raise_for_status()
    data = resp.json()
    vulns = data.get("vulnerabilities", [])
    logger.info(f"CISA KEV: {len(vulns)} entries downloaded")
    return vulns


def _kev_to_document(vuln: dict) -> dict | None:
    """Convert one KEV entry to a vector store document."""
    cve_id = vuln.get("cveID", "").strip()
    if not cve_id:
        return None

    vendor = vuln.get("vendorProject", "unknown")
    product = vuln.get("product", "")
    desc = vuln.get("shortDescription", "")
    cwe = vuln.get("cwes", [])
    cwe_str = ", ".join(cwe) if cwe else "N/A"
    date_added = vuln.get("dateAdded", "")
    due_date = vuln.get("dueDate", "")
    notes = vuln.get("notes", "")

    # Build searchable document
    parts = [
        f"CVE: {cve_id}",
        f"Vendor: {vendor}",
        f"Product: {product}",
        f"CWE: {cwe_str}",
        f"Added to KEV: {date_added}",
        f"Remediation due: {due_date}",
        f"\nDescription:\n{desc}",
    ]
    if notes:
        parts.append(f"\nNotes:\n{notes}")

    vuln_type = CWE_TYPE_MAP.get(cwe[0] if cwe else "", "unknown")
    # Mark as actively exploited — higher retrieval priority
    parts.insert(0, "[ACTIVELY EXPLOITED IN THE WILD]")

    return {
        "id": f"kev_{cve_id}",
        "document": "\n".join(parts),
        "metadata": {
            "cve_id": cve_id,
            "cwe_id": cwe_str,
            "vendor": vendor[:100],
            "product": product[:100],
            "date_added": date_added,
            "vuln_type": vuln_type,
            "source": "cisa_kev",
            "exploited": True,
        },
        "type": "kev_vuln",
    }


# =========================================================================
# NVD API downloader
# =========================================================================

def _nvd_request(api_key: str, params: dict) -> dict:
    """Make a single NVD API request with rate limiting and retry."""
    headers = {"apiKey": api_key}
    session = requests.Session()
    session.trust_env = False  # bypass system proxy

    for attempt in range(1, 4):
        try:
            resp = session.get(NVD_API, headers=headers, params=params, timeout=90)
            if resp.status_code == 403:
                logger.error("NVD API 403 — API key may be invalid or not yet activated")
                return {}
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.ProxyError:
            logger.warning(f"NVD proxy error (attempt {attempt}/3), retrying in {2**attempt}s...")
            time.sleep(2 ** attempt)
        except requests.exceptions.ConnectionError as e:
            logger.warning(f"NVD connection error (attempt {attempt}/3): {e}")
            time.sleep(2 ** attempt)
        except Exception as e:
            if attempt == 3:
                logger.warning(f"NVD request failed after 3 attempts: {e}")
                return {}
            time.sleep(2)

    return {}


def fetch_nvd_all(api_key: str) -> list[dict]:
    """Download all NVD CVEs (1999 to present), respecting rate limits.

    Walks 120-day windows from 1999-01-01 to today.
    """
    all_cves: list[dict] = []
    window = 120  # max days per NVD query

    # Walk from 1999 to now in 120-day windows
    start = "1999-01-01T00:00:00.000"
    end_date = time.strftime("%Y-%m-%dT00:00:00.000", time.gmtime())

    logger.info(f"NVD full download: {start} → {end_date} (120-day windows)")

    current_start = start
    window_count = 0
    total_expected = 0

    while current_start < end_date:
        # Calculate end of this window
        # Parse current_start, add 120 days, but don't exceed end_date
        start_dt = time.strptime(current_start[:10], "%Y-%m-%d")
        window_end = time.strftime(
            "%Y-%m-%dT00:00:00.000",
            time.gmtime(time.mktime(start_dt) + window * 86400)
        )
        if window_end > end_date:
            window_end = end_date

        window_count += 1
        # Fetch all pages for this window
        start_index = 0
        window_cves = 0

        while True:
            params = {
                "pubStartDate": current_start,
                "pubEndDate": window_end,
                "startIndex": start_index,
                "resultsPerPage": NVD_PAGE_SIZE,
            }

            data = _nvd_request(api_key, params)
            if not data:
                break

            total_results = data.get("totalResults", 0)
            if start_index == 0 and total_results > 0:
                total_expected += total_results
                logger.info(
                    f"Window {window_count}: {current_start[:10]} → {window_end[:10]} "
                    f"({total_results} CVEs, total accumulated: {total_expected})"
                )

            vulns = data.get("vulnerabilities", [])
            if not vulns:
                break

            all_cves.extend(vulns)
            window_cves += len(vulns)

            start_index += NVD_PAGE_SIZE
            if start_index >= total_results:
                break

            time.sleep(NVD_DELAY)

        logger.debug(f"  Window done: {window_cves} CVEs fetched")
        current_start = window_end
        time.sleep(0.5)  # small breather between windows

    logger.info(f"NVD download complete: {len(all_cves)} CVEs total")
    return all_cves


def _nvd_to_document(cve_item: dict) -> dict | None:
    """Convert one NVD CVE item to a vector store document."""
    cve = cve_item.get("cve", {})
    cve_id = cve.get("id", "").strip()
    if not cve_id:
        return None

    # Description
    descriptions = cve.get("descriptions", [])
    desc_en = ""
    for d in descriptions:
        if d.get("lang") == "en":
            desc_en = d.get("value", "")
            break
    if not desc_en and descriptions:
        desc_en = descriptions[0].get("value", "")

    # CWE
    weaknesses = cve.get("weaknesses", [])
    cwe_ids = []
    for w in weaknesses:
        for wd in w.get("description", []):
            cwe = wd.get("value", "")
            if cwe.startswith("CWE-"):
                cwe_ids.append(cwe)
    cwe_str = ", ".join(cwe_ids[:3]) if cwe_ids else "N/A"

    # CVSS
    metrics = cve.get("metrics", {})
    cvss_score = ""
    cvss_severity = ""
    cvss_data = (
        metrics.get("cvssMetricV31", [{}])[0] or
        metrics.get("cvssMetricV30", [{}])[0] or
        {}
    )
    if cvss_data:
        cvss_metric = cvss_data.get("cvssData", {})
        cvss_score = str(cvss_metric.get("baseScore", ""))
        cvss_severity = cvss_metric.get("baseSeverity", "")

    # Published date
    published = cve.get("published", "")

    # Vuln status
    vuln_status = cve.get("vulnStatus", "")

    vuln_type = CWE_TYPE_MAP.get(cwe_ids[0] if cwe_ids else "", "unknown")

    parts = [
        f"CVE: {cve_id}",
        f"CWE: {cwe_str}",
        f"Severity: {cvss_severity} ({cvss_score})",
        f"Status: {vuln_status}",
        f"Published: {published}",
        f"\nDescription:\n{desc_en}",
    ]

    return {
        "id": f"nvd_{cve_id}",
        "document": "\n".join(parts),
        "metadata": {
            "cve_id": cve_id,
            "cwe_id": cwe_str,
            "cvss_score": cvss_score,
            "cvss_severity": cvss_severity,
            "published": published,
            "vuln_status": vuln_status,
            "vuln_type": vuln_type,
            "source": "nvd",
            "exploited": False,
        },
        "type": "nvd_cve",
    }


# =========================================================================
# Main build logic
# =========================================================================

def build_kb(
    api_key: str = "",
    kev_only: bool = False,
    nvd_only: bool = False,
    nvd_limit: int = 0,
    batch_size: int = 500,
) -> int:
    """Build the RAG knowledge base and return total document count."""
    vector_store = VectorStore(collection_name="vuln_knowledge")

    existing = vector_store.count()
    if existing > 0 and not nvd_only:
        logger.info(
            f"Vector store already has {existing} documents — "
            f"delete data/vector_db/ to rebuild from scratch"
        )
        return existing

    total = existing if nvd_only else 0

    # Phase 1: CISA KEV (fast)
    if not nvd_only:
        logger.info("=== Phase 1: CISA KEV ===")
        kev_data = fetch_kev()
        docs = []
        for vuln in kev_data:
            doc = _kev_to_document(vuln)
            if doc:
                docs.append(doc)
        if docs:
            for i in range(0, len(docs), batch_size):
                batch = docs[i:i + batch_size]
                vector_store.add_documents(batch)
                total += len(batch)
                logger.info(f"KEV: {total}/{len(docs)} imported")
        logger.info(f"CISA KEV done: {total} documents")

    # Phase 2: NVD (slow)
    if not kev_only and api_key:
        logger.info("=== Phase 2: NVD ===")
        nvd_data = fetch_nvd_all(api_key)
        if nvd_limit and len(nvd_data) > nvd_limit:
            nvd_data = nvd_data[:nvd_limit]
        docs = []
        for item in nvd_data:
            doc = _nvd_to_document(item)
            if doc:
                docs.append(doc)
        for i in range(0, len(docs), batch_size):
            batch = docs[i:i + batch_size]
            vector_store.add_documents(batch)
            total += len(batch)
            logger.info(f"NVD: {total}/{total + len(docs) - i - len(batch)} imported")
        logger.info(f"NVD done: {len(docs)} added, {total} total")

    logger.info(f"Knowledge base built: {total} documents in vector store")
    return total


# =========================================================================
# CLI
# =========================================================================

def _load_dotenv() -> None:
    """Load .env file into os.environ."""
    env_file = Path(__file__).resolve().parent.parent / ".env"
    if not env_file.exists():
        env_file = Path(__file__).resolve().parent.parent.parent / ".env"
    if env_file.exists():
        with open(env_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k, v = k.strip(), v.strip()
                if k not in os.environ:
                    os.environ[k] = v


def main():
    _load_dotenv()

    parser = argparse.ArgumentParser(description="Build RAG knowledge base")
    parser.add_argument("--kev-only", action="store_true", help="Only CISA KEV")
    parser.add_argument("--nvd-only", action="store_true", help="Only NVD")
    parser.add_argument("--nvd-limit", type=int, default=0,
                        help="Max NVD CVEs to download (0=all)")
    parser.add_argument("--api-key", type=str, default="",
                        help="NVD API key (or set NVD_API_KEY in .env)")
    parser.add_argument("--reset", action="store_true",
                        help="Delete existing vector DB and rebuild")
    args = parser.parse_args()

    api_key = args.api_key or os.environ.get("NVD_API_KEY", "")
    if not args.kev_only and not api_key:
        logger.warning("No NVD API key provided — NVD phase will be skipped")
        logger.warning("Set --api-key or NVD_API_KEY env var")
        logger.warning("Running KEV-only mode...")
        args.kev_only = True

    if args.reset:
        import shutil
        db_path = Path("./data/vector_db")
        if db_path.exists():
            shutil.rmtree(db_path)
            logger.info(f"Deleted {db_path}")

    count = build_kb(
        api_key=api_key,
        kev_only=args.kev_only,
        nvd_only=args.nvd_only,
        nvd_limit=args.nvd_limit,
    )
    print(f"\nDone: {count} documents in knowledge base.")


if __name__ == "__main__":
    main()
