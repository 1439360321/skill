"""Vulnerability knowledge base manager.

Loads CWE definitions from JSON and populates the vector store on first use.
BigVul integration is handled separately by bigvul_loader.py.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.rag.vector_store import VectorStore
from src.utils.logger import setup_logger

logger = setup_logger()


class KnowledgeBase:
    """Manages the vulnerability knowledge base (CWE definitions + BigVul cases)."""

    def __init__(self) -> None:
        self.vector_store = VectorStore(collection_name="vuln_knowledge")
        self.kb_dir = Path("./data/knowledge_base")

    def initialize(self) -> None:
        """Load CWE data and build vector store if empty."""
        if self.is_initialized():
            logger.info(
                f"Knowledge base already initialized ({self.vector_store.count()} docs)"
            )
            return
        documents = self._load_cwe_data()
        if documents:
            self.vector_store.add_documents(documents)
            logger.info(
                f"Knowledge base initialized with {len(documents)} CWE definitions"
            )
        else:
            logger.warning("No CWE data found at %s", self.kb_dir)

    def is_initialized(self) -> bool:
        return self.vector_store.count() > 0

    def _load_cwe_data(self) -> list[dict[str, Any]]:
        cwe_file = self.kb_dir / "cwe_list.json"
        if not cwe_file.exists():
            logger.warning(f"CWE data not found at {cwe_file}")
            return []

        with open(cwe_file, "r", encoding="utf-8") as fh:
            cwes = json.load(fh)

        # Ensure each CWE has a type marker and id
        for cwe in cwes:
            cwe.setdefault("type", "cwe")
            if "id" not in cwe:
                cwe["id"] = cwe.get("cwe_id", f"CWE-{cwe.get('ID', 'UNKNOWN')}")
            # Build searchable document field from CWE fields
            if "document" not in cwe:
                cwe["document"] = self._format_cwe_doc(cwe)

        return cwes

    @staticmethod
    def _format_cwe_doc(cwe: dict) -> str:
        name = cwe.get("Name", cwe.get("name", "Unknown"))
        desc = cwe.get("Description", cwe.get("description", ""))
        mitigation = cwe.get("Potential Mitigations", cwe.get("mitigation", ""))
        parts = [f"CWE: {name}"]
        if desc:
            parts.append(f"Description: {desc}")
        if mitigation:
            parts.append(f"Mitigation: {mitigation}")
        return "\n".join(parts)
