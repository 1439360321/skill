"""SCA (Software Composition Analysis) scanner.

Parse dependency manifests (requirements.txt, pom.xml) and query OSV.dev
for known vulnerabilities.  Results are cached locally for 24 hours to
avoid rate-limiting and speed up repeated scans.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

import requests

from src.utils.logger import setup_logger

logger = setup_logger()


class SCAScanner:
    """Scan project dependencies for known CVEs via OSV API."""

    OSV_QUERY_URL = "https://api.osv.dev/v1/query"
    OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"

    ECOSYSTEM_MAP = {
        "requirements.txt": "PyPI",
        "setup.py": "PyPI",
        "Pipfile": "PyPI",
        "pom.xml": "Maven",
    }

    def __init__(self, cache_dir: str = "./data/cache") -> None:
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_file = self.cache_dir / "osv_cache.json"
        self._cache: dict[str, Any] = self._load_cache()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self, project_path: str) -> list[dict[str, Any]]:
        """Scan *project_path* and return a list of dependency vulnerabilities."""
        dependencies = self._parse_dependencies(project_path)
        if not dependencies:
            logger.info("No dependencies found in project")
            return []

        logger.info(f"Found {len(dependencies)} dependencies, checking OSV...")
        results = self._query_with_cache(dependencies)
        logger.info(f"SCA complete: {len(results)} vulnerabilities found")
        return results

    # ------------------------------------------------------------------
    # Dependency parsing
    # ------------------------------------------------------------------

    def _parse_dependencies(self, project_path: str) -> list[dict[str, str]]:
        """Parse all supported dependency manifests in *project_path*."""
        deps: list[dict[str, str]] = []
        root = Path(project_path)

        # Python: requirements.txt
        req_file = root / "requirements.txt"
        if req_file.exists():
            for line in req_file.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                for sep in ("==", ">=", "<=", "~=", "!=", ">"):
                    if sep in line:
                        pkg, ver = line.split(sep, 1)
                        deps.append(
                            {
                                "name": pkg.strip(),
                                "version": ver.strip(),
                                "ecosystem": "PyPI",
                            }
                        )
                        break

        # Python: setup.py (basic regex extraction)
        setup_file = root / "setup.py"
        if setup_file.exists():
            content = setup_file.read_text(encoding="utf-8")
            for m in re.finditer(
                r"""['"]([^'"]+)['"]\s*[:>=]=?\s*['"]([^'"]+)['"]""",
                content,
            ):
                deps.append(
                    {
                        "name": m.group(1).strip(),
                        "version": m.group(2).strip(),
                        "ecosystem": "PyPI",
                    }
                )

        # Java: pom.xml
        pom_file = root / "pom.xml"
        if pom_file.exists():
            deps.extend(self._parse_pom(pom_file))

        return deps

    def _parse_pom(self, pom_path: Path) -> list[dict[str, str]]:
        """Extract dependencies from a Maven pom.xml."""
        deps: list[dict[str, str]] = []
        content = pom_path.read_text(encoding="utf-8")

        # Extract <properties> for variable substitution
        props: dict[str, str] = {}
        for m in re.finditer(
            r"<([^>]+)>([^<]+)</\1>",
            content,
        ):
            props[m.group(1)] = m.group(2)

        # Extract <dependency> blocks
        dep_pattern = re.compile(
            r"<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*<version>\$\{([^}]+)\}</version>",
            re.DOTALL,
        )
        for m in dep_pattern.finditer(content):
            group = m.group(1)
            artifact = m.group(2)
            version_ref = m.group(3)
            version = props.get(version_ref, version_ref)
            deps.append(
                {
                    "name": f"{group}:{artifact}",
                    "version": version,
                    "ecosystem": "Maven",
                }
            )

        # Fixed-version dependencies
        fixed_pattern = re.compile(
            r"<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*<version>([^<$]+)</version>",
            re.DOTALL,
        )
        for m in fixed_pattern.finditer(content):
            group = m.group(1)
            artifact = m.group(2)
            version = m.group(3)
            deps.append(
                {
                    "name": f"{group}:{artifact}",
                    "version": version,
                    "ecosystem": "Maven",
                }
            )

        return deps

    # ------------------------------------------------------------------
    # OSV query with local cache
    # ------------------------------------------------------------------

    def _load_cache(self) -> dict[str, Any]:
        if self.cache_file.exists():
            try:
                data = json.loads(self.cache_file.read_text(encoding="utf-8"))
                logger.debug(f"Loaded OSV cache: {len(data)} entries")
                return data
            except Exception:
                pass
        return {}

    def _save_cache(self) -> None:
        try:
            self.cache_file.write_text(
                json.dumps(self._cache, indent=2),
                encoding="utf-8",
            )
        except Exception as e:
            logger.warning(f"Failed to save OSV cache: {e}")

    def _cache_key(self, dep: dict[str, str]) -> str:
        return f"{dep['ecosystem']}:{dep['name']}:{dep['version']}"

    def _cache_get(self, dep: dict[str, str]) -> list[dict[str, Any]] | None:
        key = self._cache_key(dep)
        entry = self._cache.get(key)
        if entry is None:
            return None
        # Check TTL (24h)
        if time.time() - entry.get("_ts", 0) > 86400:
            return None
        return entry.get("vulns", [])

    def _cache_set(self, dep: dict[str, str], vulns: list[dict[str, Any]]) -> None:
        key = self._cache_key(dep)
        self._cache[key] = {"_ts": time.time(), "vulns": vulns}
        self._save_cache()

    def _query_with_cache(
        self,
        deps: list[dict[str, str]],
    ) -> list[dict[str, Any]]:
        """Query OSV API, using cache when possible."""
        results: list[dict[str, Any]] = []
        uncached: list[dict[str, str]] = []

        for dep in deps:
            cached = self._cache_get(dep)
            if cached is not None:
                for v in cached:
                    results.append({"package": dep["name"], "version": dep["version"], **v})
            else:
                uncached.append(dep)

        if uncached:
            live = self._query_osv(uncached)
            # Index live results by package name
            live_idx: dict[str, list[dict]] = {}
            for r in live:
                live_idx.setdefault(r["package"], []).append(r)

            for dep in uncached:
                vulns_for_dep = live_idx.get(dep["name"], [])
                stripped = [
                    {k: v for k, v in v.items() if k not in ("package", "version")}
                    for v in vulns_for_dep
                ]
                self._cache_set(dep, stripped)
                results.extend(vulns_for_dep)

        return results

    def _query_osv(
        self,
        dependencies: list[dict[str, str]],
    ) -> list[dict[str, Any]]:
        """Send a batch query to the OSV API."""
        queries = []
        for dep in dependencies:
            queries.append(
                {
                    "package": {
                        "name": dep["name"],
                        "ecosystem": dep.get("ecosystem", "PyPI"),
                    },
                    "version": dep["version"],
                }
            )
        if not queries:
            return []

        try:
            resp = requests.post(
                self.OSV_BATCH_URL,
                json={"queries": queries},
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
        except requests.Timeout:
            logger.error("OSV API request timed out")
            return []
        except Exception as e:
            logger.error(f"OSV API query failed: {e}")
            return []

        results: list[dict[str, Any]] = []
        for i, result in enumerate(data.get("results", [])):
            dep = dependencies[i]
            for vuln in result.get("vulns", []):
                aliases = vuln.get("aliases", [])
                cve_id = aliases[0] if aliases else vuln.get("id", "N/A")

                severity = "UNKNOWN"
                cvss_score = None
                db_specific = vuln.get("database_specific", {})
                if "severity" in db_specific:
                    severity = db_specific["severity"]
                # Try CVSS score
                for sev in vuln.get("severity", []):
                    if sev.get("type") == "CVSS_V3":
                        cvss_score = sev.get("score")
                        break

                results.append(
                    {
                        "package": dep["name"],
                        "version": dep["version"],
                        "ecosystem": dep.get("ecosystem", ""),
                        "cve_id": cve_id,
                        "summary": vuln.get("summary", "")[:200],
                        "severity": severity,
                        "cvss_score": cvss_score,
                        "fixed_version": self._extract_fixed(vuln),
                        "url": vuln.get("references", [{}])[0].get("url", ""),
                    }
                )
        return results

    def _extract_fixed(self, vuln: dict) -> str:
        """Try to extract the first fixed version from affected ranges."""
        for affected in vuln.get("affected", []):
            for r in affected.get("ranges", []):
                for event in r.get("events", []):
                    if "fixed" in event:
                        return event["fixed"]
        return ""
