"""LLM 客户端工厂函数 -- 从 session state 构建客户端，各页面共享."""
from __future__ import annotations

import json
from pathlib import Path

import streamlit as st

# ===========================================================================
# Config persistence — survive browser refresh
# ===========================================================================

_CONFIG_PATH = Path(__file__).resolve().parent.parent.parent / ".code-audit-config.json"

_PERSIST_KEYS = [
    "llm_provider", "llm_base_url", "llm_model", "llm_api_key",
    "llm_ollama_host", "llm_ollama_model",
    "pipeline_preset",
]


def load_config() -> dict:
    """Load persisted LLM config from disk. Returns empty dict if not found."""
    try:
        if _CONFIG_PATH.exists():
            return json.loads(_CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}


def save_config() -> None:
    """Persist current LLM config to disk."""
    try:
        data = {k: st.session_state.get(k) for k in _PERSIST_KEYS}
        _CONFIG_PATH.write_text(
            json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8",
        )
    except Exception:
        pass  # never crash on save


def get_llm_client():
    """从 session state 构建 LLM 客户端。返回客户端对象或 None（未配置 API Key）。"""
    provider = st.session_state.get("llm_provider", "openai")

    if provider == "openai":
        api_key = st.session_state.get("llm_api_key", "")
        if not api_key:
            return None
        import sys
        from pathlib import Path
        _ROOT = Path(__file__).resolve().parent.parent.parent
        sys.path.insert(0, str(_ROOT))
        sys.path.insert(0, str(_ROOT.parent))
        from shared.llm.openai_client import OpenAIClient
        return OpenAIClient(
            api_key=api_key,
            base_url=st.session_state.get("llm_base_url", "https://open.bigmodel.cn/api/paas/v4"),
            model=st.session_state.get("llm_model", "glm-4.6v"),
        )
    else:
        import sys
        from pathlib import Path
        _ROOT = Path(__file__).resolve().parent.parent.parent
        sys.path.insert(0, str(_ROOT))
        sys.path.insert(0, str(_ROOT.parent))
        from shared.llm.ollama_client import OllamaClient
        return OllamaClient(
            host=st.session_state.get("llm_ollama_host", "http://localhost:11434"),
            model=st.session_state.get("llm_ollama_model", "deepseek-r1:8b"),
        )


def test_llm_connection() -> bool:
    """测试 LLM 连通性并将结果写入 session state。"""
    client = get_llm_client()
    if client is None:
        st.session_state.llm_connected = False
        return False
    try:
        ok = client.check_health()
        st.session_state.llm_connected = ok
        return ok
    except Exception:
        st.session_state.llm_connected = False
        return False
