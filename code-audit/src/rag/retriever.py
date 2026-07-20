"""RAG retriever — converts code slices into search queries and retrieves
similar vulnerability cases from the vector store.

Upgraded from the original keyword-mapping approach to use richer context:
sink category, dataflow path, language, and sanitization status.

Supports hybrid retrieval: vector similarity (ChromaDB) + BM25 keyword scoring,
fused via Reciprocal Rank Fusion (RRF) for better precision.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any

from src.rag.vector_store import VectorStore
from src.utils.logger import setup_logger

logger = setup_logger()


# ---------------------------------------------------------------------------
# Simple BM25 implementation (no external deps)
# ---------------------------------------------------------------------------

class _BM25Scorer:
    """Minimal BM25 scorer for keyword-dense retrieval."""

    def __init__(self, k1: float = 1.2, b: float = 0.75):
        self.k1 = k1
        self.b = b

    def _tokenize(self, text: str) -> list[str]:
        """Lowercase, split on non-alphanumeric, filter short tokens."""
        return [t.lower() for t in re.findall(r"[a-zA-Z_]\w+", text) if len(t) > 1]

    def score(self, query: str, document: str, corpus_docs: list[str]) -> float:
        """Score a single document against a query using corpus statistics."""
        q_terms = self._tokenize(query)
        doc_terms = self._tokenize(document)
        if not q_terms or not doc_terms:
            return 0.0

        doc_len = len(doc_terms)
        avg_dl = sum(len(self._tokenize(d)) for d in corpus_docs) / max(1, len(corpus_docs))
        doc_tf = Counter(doc_terms)
        df: Counter[str] = Counter()
        for d in corpus_docs:
            df.update(set(self._tokenize(d)))
        N = len(corpus_docs)

        score = 0.0
        for term in set(q_terms):
            tf = doc_tf.get(term, 0)
            if tf == 0:
                continue
            idf = math.log((N - df.get(term, 0) + 0.5) / (df.get(term, 0) + 0.5) + 1.0)
            numerator = tf * (self.k1 + 1)
            denominator = tf + self.k1 * (1 - b + b * doc_len / max(1, avg_dl))
            score += idf * numerator / denominator
        return score


# ---------------------------------------------------------------------------
# Retriever
# ---------------------------------------------------------------------------


class RAGRetriever:
    """Retrieve relevant vulnerability knowledge for code slices.

    Supports hybrid retrieval: vector + BM25 fused via RRF.
    """

    def __init__(self) -> None:
        self.vector_store = VectorStore(collection_name="vuln_knowledge")
        self._bm25 = _BM25Scorer()

    def retrieve_for_code(
        self,
        code: str,
        language: str,
        top_k: int | None = None,
        *,
        use_hybrid: bool = True,
    ) -> list[dict[str, Any]]:
        """Retrieve the most relevant vulnerability cases for a code slice.

        Args:
            code: The code snippet to find similar cases for.
            language: Programming language ('c', 'python', or 'java').
            top_k: Number of results (defaults to config value).
            use_hybrid: Enable BM25+vector hybrid retrieval (RRF fusion).
        """
        from src.config import Config

        if top_k is None:
            top_k = Config().rag.get("top_k", 5)

        query = self._code_to_query(code, language)
        threshold = Config().rag.get("similarity_threshold", 0.6)

        # Vector retrieval
        vec_results = self.vector_store.query(
            query,
            top_k=top_k * 2,  # fetch more for fusion
            similarity_threshold=threshold,
        )

        if not use_hybrid or not vec_results:
            return vec_results[:top_k]

        # BM25 keyword scoring against the same document pool
        corpus = [r.get("document", "") for r in vec_results]
        bm25_scores = [
            self._bm25.score(query, doc, corpus)
            for doc in corpus
        ]

        # RRF fusion: score = 1/(k + rank) for each method
        k_rrf = 60
        vec_ranked = sorted(vec_results, key=lambda r: r.get("similarity", 0), reverse=True)
        bm25_ranked = sorted(
            zip(vec_results, bm25_scores),
            key=lambda x: x[1], reverse=True,
        )

        # Assign RRF scores
        rrf_scores: dict[str, float] = {}
        for rank, r in enumerate(vec_ranked):
            rrf_scores[r["id"]] = rrf_scores.get(r["id"], 0) + 1.0 / (k_rrf + rank + 1)
        for rank, (r, _) in enumerate(bm25_ranked):
            rrf_scores[r["id"]] = rrf_scores.get(r["id"], 0) + 1.0 / (k_rrf + rank + 1)

        # Re-rank by RRF
        fused = sorted(vec_results, key=lambda r: rrf_scores.get(r["id"], 0), reverse=True)

        logger.debug(
            f"Hybrid retrieval: {len(vec_results)} vector → {len(fused)} fused, "
            f"query: {query[:80]}..."
        )
        return fused[:top_k]

    def retrieve_gated(
        self,
        code: str,
        language: str,
        ast_confidence: float,
        top_k: int | None = None,
    ) -> list[dict[str, Any]]:
        """Confidence-gated retrieval — only triggers RAG for borderline cases.

        * ast_confidence > 0.7: skip RAG (static analysis is confident enough)
        * ast_confidence 0.4–0.7: full hybrid retrieval
        * ast_confidence < 0.4: skip RAG (too uncertain, rely on LLM semantic review)

        This saves embedding compute and avoids polluting prompts with
        low-quality retrieval results.
        """
        if ast_confidence > 0.7:
            logger.debug(f"RAG skipped: confidence {ast_confidence:.2f} > 0.7")
            return []
        if ast_confidence < 0.4:
            logger.debug(f"RAG skipped: confidence {ast_confidence:.2f} < 0.4")
            return []
        return self.retrieve_for_code(code, language, top_k=top_k)

    # ------------------------------------------------------------------
    # Query construction — upgraded from simple keyword mapping
    # ------------------------------------------------------------------

    def _code_to_query(self, code: str, language: str) -> str:
        """Build a natural-language query from source code and language.

        Uses sink/source pattern matching, NOT the old hard-coded keyword map.
        """
        parts: list[str] = [f"{language} security vulnerability"]

        # Sink detection via pattern matching
        sink_keywords = self._extract_sink_keywords(code, language)
        if sink_keywords:
            parts.append(f"dangerous function: {' '.join(sink_keywords[:3])}")

        # Detect source patterns
        source_patterns = self._extract_source_indicators(code, language)
        if source_patterns:
            parts.append(f"user input: {' '.join(source_patterns[:2])}")

        # Language-specific context
        if language == "c":
            parts.append("C programming buffer memory string")
        elif language == "python":
            parts.append("Python code injection deserialization")
        elif language == "java":
            parts.append("Java web application vulnerability")

        return "; ".join(parts)

    def _extract_sink_keywords(self, code: str, language: str) -> list[str]:
        """Find sink function names present in the code."""
        from src.scanner.sink_registry import SINKS

        found: list[str] = []
        for category, functions in SINKS.get(language, {}).items():
            for func in functions:
                base_name = func.split(".")[-1].rstrip("(") if "." in func else func
                if base_name and base_name in code:
                    found.append(f"{func}({category})")
                    if len(found) >= 3:
                        return found
        return found

    def _extract_source_indicators(self, code: str, language: str) -> list[str]:
        """Find source/input indicators in the code."""
        from src.scanner.sink_registry import SOURCES

        found: list[str] = []
        for category in ("function_calls", "objects", "variables"):
            for item in SOURCES.get(language, {}).get(category, []):
                if item in code:
                    found.append(item)
                    if len(found) >= 3:
                        return found
        return found
