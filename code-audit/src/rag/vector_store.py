"""ChromaDB vector store wrapper for vulnerability knowledge.

Uses SiliconFlow embedding API (BAAI/bge-m3, 1024-dim, multilingual, free tier)
via ChromaDB's EmbeddingFunction interface. Falls back to ONNX if no API key.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

import requests
from chromadb import PersistentClient
from chromadb.api.types import Documents, EmbeddingFunction, Embeddings

from src.utils.logger import setup_logger

logger = setup_logger()

SF_API_URL = "https://api.siliconflow.cn/v1/embeddings"
SF_MODEL = "BAAI/bge-m3"
SF_DIM = 1024
SF_BATCH = 32  # max batch size per API call
SF_RETRY = 3


def _load_dotenv() -> None:
    """Load .env into os.environ."""
    cur = Path(__file__).resolve().parent
    for _ in range(5):
        env_file = cur / ".env"
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
            return
        cur = cur.parent


# ---------------------------------------------------------------------------
# SiliconFlow EmbeddingFunction
# ---------------------------------------------------------------------------

class SiliconFlowEmbedding(EmbeddingFunction):
    """ChromaDB EmbeddingFunction backed by SiliconFlow API.

    Uses Qwen3-Embedding-0.6B (1024-dim), trained for code search.
    """

    def __init__(self, api_key: str, model: str = SF_MODEL):
        self.api_key = api_key
        self.model = model

    def __call__(self, inputs: Documents) -> Embeddings:
        """Batch-embed a list of texts, respecting API limits."""
        all_embeddings: list[list[float]] = []

        for i in range(0, len(inputs), SF_BATCH):
            batch = inputs[i : i + SF_BATCH]
            batch_embs = self._embed_batch(batch)
            all_embeddings.extend(batch_embs)

        return all_embeddings

    def _embed_batch(self, texts: list[str]) -> list[list[float]]:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "input": texts,
        }

        for attempt in range(1, SF_RETRY + 1):
            try:
                resp = requests.post(SF_API_URL, headers=headers, json=payload, timeout=60)
                if resp.status_code == 429:
                    time.sleep(min(2 ** attempt, 30))
                    continue
                resp.raise_for_status()
                data = resp.json()
                items = sorted(data.get("data", []), key=lambda x: x.get("index", 0))
                return [item.get("embedding", []) for item in items]
            except Exception as e:
                if attempt == SF_RETRY:
                    logger.warning(f"SiliconFlow embedding failed after {SF_RETRY} attempts: {e}")
                else:
                    time.sleep(1)

        return [[] for _ in texts]


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def _create_embedding_function():
    """Pick the best available embedding function.

    1. SiliconFlow API (if SILICONFLOW_API_KEY is set)
    2. ONNX all-MiniLM-L6-v2 (local fallback)
    """
    _load_dotenv()

    sf_key = os.environ.get("SILICONFLOW_API_KEY", "")
    if sf_key:
        logger.info(f"Embedding: SiliconFlow {SF_MODEL} ({SF_DIM}-dim, free tier)")
        return SiliconFlowEmbedding(api_key=sf_key)

    # Fallback: ONNX
    try:
        from chromadb.utils.embedding_functions import ONNXMiniLM_L6_V2

        logger.info("Embedding: ONNX all-MiniLM-L6-v2 (384-dim, CPU)")
        return ONNXMiniLM_L6_V2(preferred_providers=["CPUExecutionProvider"])
    except ImportError:
        logger.warning("No embedding backend available. Install chromadb or set SILICONFLOW_API_KEY.")
        return None


# ---------------------------------------------------------------------------
# VectorStore
# ---------------------------------------------------------------------------

class VectorStore:
    """Persistent vector store for CWE definitions and vulnerability cases."""

    def __init__(
        self,
        collection_name: str = "vuln_knowledge",
        db_path: str | None = None,
    ) -> None:
        if db_path is None:
            db_path = str(Path("./data/vector_db"))

        self.db_path = Path(db_path)
        self.db_path.mkdir(parents=True, exist_ok=True)

        self.client = PersistentClient(path=str(self.db_path))
        self.embedding_fn = _create_embedding_function()

        self.collection = self.client.get_or_create_collection(
            name=collection_name,
            embedding_function=self.embedding_fn,
        )

    # ------------------------------------------------------------------
    # Write API
    # ------------------------------------------------------------------

    def add_documents(self, documents: list[dict[str, Any]]) -> None:
        """Insert a batch of documents.

        Each dict must contain: ``id``, ``document`` (text), ``metadata``.
        """
        ids: list[str] = []
        texts: list[str] = []
        metadatas: list[dict[str, Any]] = []

        for d in documents:
            doc_id = d.get("id", "")
            if not doc_id:
                continue
            ids.append(doc_id)
            texts.append(d.get("document", ""))
            meta = d.get("metadata", {})
            meta["type"] = d.get("type", "unknown")
            metadatas.append(meta)

        if ids:
            self.collection.add(ids=ids, documents=texts, metadatas=metadatas)

    # ------------------------------------------------------------------
    # Read API
    # ------------------------------------------------------------------

    def query(
        self,
        query_text: str,
        top_k: int = 5,
        similarity_threshold: float = 0.5,
    ) -> list[dict[str, Any]]:
        """Retrieve the *top_k* most similar documents."""
        if self.collection.count() == 0:
            return []

        try:
            results = self.collection.query(
                query_texts=[query_text],
                n_results=min(top_k, self.collection.count()),
            )
        except Exception as e:
            logger.warning(f"Vector query failed: {e}")
            return []

        output: list[dict[str, Any]] = []
        ids = results.get("ids", [[]])[0]
        docs = results.get("documents", [[]])[0]
        metas = results.get("metadatas", [[]])[0]
        distances = results.get("distances", [[]])[0]

        for i, doc_id in enumerate(ids):
            similarity = 1.0 - float(distances[i]) if i < len(distances) else 0.0
            if similarity < similarity_threshold:
                continue
            output.append({
                "id": doc_id,
                "document": docs[i] if i < len(docs) else "",
                "metadata": metas[i] if i < len(metas) else {},
                "similarity": round(similarity, 4),
            })
        return output

    def count(self) -> int:
        try:
            return self.collection.count()
        except Exception:
            return 0
