"""BigVul dataset loader — parse the CSV and import into ChromaDB.

The BigVul CSV (all_c_cpp_release2.0.csv) contains CVE metadata:
CVE ID, CWE ID, CVSS score, vulnerability summary, project, language.

Since this release doesn't bundle vulnerable/patched code, we build
searchable documents from the CVE summary + metadata fields.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from src.rag.vector_store import VectorStore
from src.utils.logger import setup_logger

logger = setup_logger()


class BigVulLoader:
    """Parse the BigVul CSV and populate the ChromaDB vector store."""

    def __init__(
        self,
        csv_path: str,
        vector_store: VectorStore | None = None,
    ) -> None:
        self.csv_path = Path(csv_path)
        self.vector_store = vector_store or VectorStore(
            collection_name="vuln_knowledge",
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load(
        self,
        max_samples: int = 500,
        min_summary_length: int = 30,
    ) -> int:
        """Parse CSV and insert into vector store.

        Returns the number of documents inserted.
        """
        if not self.csv_path.exists():
            raise FileNotFoundError(f"BigVul CSV not found: {self.csv_path}")

        existing = self.vector_store.count()
        if existing > 0:
            logger.info(
                f"Vector store already has {existing} docs — skipping BigVul import"
            )
            return 0

        documents = self._parse_csv(max_samples, min_summary_length)
        if documents:
            self.vector_store.add_documents(documents)
            logger.info(f"Imported {len(documents)} BigVul cases into vector store")
        else:
            logger.warning("No valid BigVul cases found in CSV")
        return len(documents)

    # ------------------------------------------------------------------
    # CSV parsing
    # ------------------------------------------------------------------

    def _parse_csv(
        self,
        max_samples: int,
        min_summary_len: int,
    ) -> list[dict[str, Any]]:
        """Read the CSV and build document dicts."""
        docs: list[dict[str, Any]] = []
        seen: set[str] = set()

        with open(self.csv_path, "r", encoding="utf-8", errors="replace") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                if len(docs) >= max_samples:
                    break

                cve_id = (row.get("cve_id") or "").strip()
                if not cve_id or not cve_id.startswith("CVE-"):
                    continue

                summary = (row.get("summary") or "").strip()
                if len(summary) < min_summary_len:
                    continue

                # Dedup by CVE
                if cve_id in seen:
                    continue
                seen.add(cve_id)

                cwe_id = (row.get("cwe_id") or "N/A").strip()
                project = (row.get("project") or "unknown").strip()
                language = (row.get("lang") or "c").strip()
                cvss = row.get("score", "").strip()
                pub_date = row.get("publish_date", "").strip()

                doc_text = self._build_doc(
                    cve_id, cwe_id, summary, project, language, cvss, pub_date
                )

                meta = {
                    "cve_id": cve_id,
                    "cwe_id": cwe_id,
                    "language": language[:20],
                    "project": project[:100],
                    "cvss_score": cvss,
                    "publish_date": pub_date,
                    "vuln_type": self._infer_vuln_type(cwe_id, summary),
                    "has_fix": False,  # this CSV release doesn't include code
                }

                docs.append(
                    {
                        "id": f"bigvul_{cve_id}",
                        "document": doc_text,
                        "metadata": meta,
                        "type": "bigvul_case",
                    }
                )

        return docs

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_doc(
        cve_id: str,
        cwe_id: str,
        summary: str,
        project: str,
        language: str,
        cvss: str,
        pub_date: str,
    ) -> str:
        parts = [
            f"CVE: {cve_id}",
            f"CWE: {cwe_id}",
            f"Language: {language}",
            f"Project: {project}",
        ]
        if cvss:
            parts.append(f"CVSS: {cvss}")
        if pub_date:
            parts.append(f"Published: {pub_date}")
        parts.append(f"\nDescription:\n{summary}")
        return "\n".join(parts)

    @staticmethod
    def _infer_vuln_type(cwe_id: str, summary: str) -> str:
        """Infer vulnerability type from CWE or summary text."""
        cwe_map = {
            "CWE-121": "buffer_overflow",
            "CWE-122": "buffer_overflow",
            "CWE-125": "out_of_bounds_read",
            "CWE-787": "out_of_bounds_write",
            "CWE-134": "format_string",
            "CWE-78": "command_injection",
            "CWE-77": "command_injection",
            "CWE-89": "sql_injection",
            "CWE-416": "use_after_free",
            "CWE-415": "double_free",
            "CWE-476": "null_pointer",
            "CWE-190": "integer_overflow",
            "CWE-20": "input_validation",
            "CWE-119": "buffer_overflow",
            "CWE-189": "integer_overflow",
            "CWE-200": "information_disclosure",
            "CWE-264": "privilege_escalation",
            "CWE-362": "race_condition",
            "CWE-399": "resource_exhaustion",
        }
        return cwe_map.get(cwe_id, "unknown")


def load_bigvul_from_script(
    csv_path: str,
    max_samples: int = 500,
) -> int:
    """Entry point for scripts/prepare_bigvul.py."""
    loader = BigVulLoader(csv_path)
    return loader.load(max_samples=max_samples)
