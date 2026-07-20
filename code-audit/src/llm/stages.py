"""Multi-stage LLM inference pipeline.

Stage 1 — Quick triage: filter out obviously-safe slices.
Stage 2 — CoT deep analysis with RAG: thorough vulnerability assessment.
Stage 3 — Self-verification: LLM reviews its own finding for false positives.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from src.config import Config
from src.llm.prompt_builder import PromptBuilder
from src.llm.parser import LLMOutputParser
from src.scanner.sanitization import SanitizationDetector
from src.utils.logger import setup_logger

# Ensure project root on path for shared.llm
_PROJ_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(_PROJ_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJ_ROOT))

# Load .env
def _load_dotenv() -> None:
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

_load_dotenv()
from shared.llm.openai_client import create_llm_client

# Lazy import — RAG may not be available in all environments
try:
    from src.rag.retriever import RAGRetriever
    _HAS_RAG = True
except ImportError:
    _HAS_RAG = False
    RAGRetriever = None  # type: ignore

logger = setup_logger()

# Sinks that always warrant deep analysis (skip Stage 1)
_HIGH_PRIORITY_SINKS = {
    "system", "eval", "exec", "strcpy", "gets", "sprintf",
    "pickle.loads", "pickle.load", "yaml.load",
    "os.system", "subprocess.Popen", "subprocess.call",
    "Runtime.exec", "ProcessBuilder",
}


class StageRunner:
    """Orchestrates Stage 1 → 2 → 3 for each suspicious code slice."""

    def __init__(
        self,
        mode: str = "rag",
        enable_multistage: bool = True,
    ) -> None:
        self.mode = mode
        self.enable_multistage = enable_multistage
        llm_cfg = Config()._data.get("llm", Config()._data.get("ollama", {}))
        self.client = create_llm_client(dict(llm_cfg))
        self.retriever: RAGRetriever | None = None
        if mode == "rag":
            if not _HAS_RAG or RAGRetriever is None:
                logger.warning("RAG mode requested but chromadb not available — falling back to baseline")
                self.mode = "baseline"
            else:
                try:
                    self.retriever = RAGRetriever()
                except ImportError as e:
                    logger.warning(f"RAG initialization failed: {e} — falling back to baseline")
                    self.mode = "baseline"

        # Read token limits from config (R1 needs more for think blocks)
        cfg = Config()
        ms = cfg.multistage
        self.stage1_tokens = ms.get("stage1_max_tokens", 1024)
        self.stage2_tokens = ms.get("stage2_max_tokens", 2048)
        self.stage3_tokens = ms.get("stage3_max_tokens", 1024)

    def run(self, slice_data: dict) -> dict | None:
        """Run the full pipeline on a single code slice. Returns the final
        validated result, or *None* if the slice was filtered out by Stage 1.
        """
        language = slice_data.get("language", "python")
        code = slice_data.get("code", "")
        sink_category = slice_data.get("sink_category", "")

        # Stage 1: Quick triage (skippable)
        if self._should_skip_stage1(slice_data):
            logger.debug(f"  [{slice_data.get('function_name', '?')}] Skipping Stage 1")
        else:
            suspicious = self._run_stage1(code, language)
            if not suspicious:
                logger.debug(
                    f"  [{slice_data.get('function_name', '?')}] Stage 1: SAFE — filtered"
                )
                return None
            logger.debug(
                f"  [{slice_data.get('function_name', '?')}] Stage 1: SUSPICIOUS"
            )

        # Stage 2: CoT deep analysis
        retrieved = None
        if self.retriever:
            retrieved = self.retriever.retrieve_for_code(code, language)

        stage2_result = self._run_stage2(code, language, slice_data, retrieved)

        if stage2_result is None:
            return None

        # Stage 3: Self-verification
        if self.enable_multistage:
            stage3_correction = self._run_stage3(code, language, stage2_result)
            if stage3_correction:
                stage2_result.update(stage3_correction)

        # Merge slice metadata into result
        stage2_result["file"] = slice_data.get("file", "")
        stage2_result["function_name"] = slice_data.get("function_name", "")
        stage2_result["line_start"] = slice_data.get("line_start", 0)
        stage2_result["line_end"] = slice_data.get("line_end", 0)
        stage2_result["language"] = language
        stage2_result["mode"] = self.mode
        stage2_result["sink_type"] = slice_data.get("sink_type", "")
        stage2_result["code"] = code

        return stage2_result

    # ------------------------------------------------------------------
    # Stage 1 — Quick triage
    # ------------------------------------------------------------------

    def _run_stage1(self, code: str, language: str) -> bool:
        """Return True if the code looks suspicious (needs Stage 2)."""
        prompt = PromptBuilder.build_stage1(code, language)
        try:
            response = self.client.generate(
                prompt,
                temperature=0.0,
                max_tokens=self.stage1_tokens,
            )
            parsed = LLMOutputParser.parse(response)
            if parsed is None:
                return True  # err on the side of caution
            return parsed.get("suspicious", True)
        except Exception as e:
            logger.warning(f"Stage 1 failed: {e} — falling through to Stage 2")
            return True

    def _should_skip_stage1(self, slice_data: dict) -> bool:
        """Determine whether Stage 1 should be skipped for this slice."""
        if not self.enable_multistage:
            return True  # skip means go straight to Stage 2

        # High-confidence AST signals
        if slice_data.get("ast_confidence", 0) >= 0.8:
            return True
        if slice_data.get("risk_level") == "high":
            return True
        # No sanitization + high-risk sink
        if not slice_data.get("has_sanitization"):
            if slice_data.get("sink_type", "") in _HIGH_PRIORITY_SINKS:
                return True
        return False

    # ------------------------------------------------------------------
    # Stage 2 — CoT deep analysis
    # ------------------------------------------------------------------

    def _run_stage2(
        self,
        code: str,
        language: str,
        slice_data: dict,
        retrieved: list[dict] | None,
    ) -> dict | None:
        """Deep analysis with CoT + RAG context."""
        # Build few-shot examples from retrieved cases
        few_shot_text = ""
        if retrieved:
            few_shot_text = PromptBuilder.build_few_shot(
                code, language, retrieved, max_examples=2
            )

        prompt = PromptBuilder.build_stage2(
            code=code,
            language=language,
            slice_data=slice_data,
            retrieved_cases=retrieved or [],
            few_shot_text=few_shot_text,
        )
        try:
            response = self.client.generate(
                prompt,
                temperature=0.1,
                max_tokens=self.stage2_tokens,
            )
            return LLMOutputParser.parse_and_validate(response)
        except Exception as e:
            logger.error(f"Stage 2 failed: {e}")
            return None

    # ------------------------------------------------------------------
    # Stage 3 — Self-verification
    # ------------------------------------------------------------------

    def _run_stage3(
        self,
        code: str,
        language: str,
        stage2_result: dict,
    ) -> dict | None:
        """Let the LLM review its own finding."""
        prompt = PromptBuilder.build_stage3(
            code=code,
            language=language,
            finding=stage2_result,
        )
        try:
            response = self.client.generate(
                prompt,
                temperature=0.2,
                max_tokens=self.stage3_tokens,
            )
            parsed = LLMOutputParser.parse(response)
            if parsed is None:
                return None
            # Apply corrections
            correction = {}
            if "adjusted_confidence" in parsed:
                correction["confidence"] = float(parsed["adjusted_confidence"])
            if "adjusted_severity" in parsed:
                correction["severity"] = parsed["adjusted_severity"]
            if not parsed.get("confirmed", True):
                correction["has_vulnerability"] = False
                correction["false_positive_reason"] = parsed.get(
                    "false_positive_reason", ""
                )
            if "refined_description" in parsed:
                correction["description"] = parsed["refined_description"]
            return correction
        except Exception as e:
            logger.warning(f"Stage 3 failed: {e}")
            return None
