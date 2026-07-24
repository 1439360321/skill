"""管道阶段可视化 -- 展示每层输出和时间."""
from __future__ import annotations

import streamlit as st


def render_pipeline_result(result: dict, elapsed: float = 0.0) -> None:
    """渲染完整管道结果。默认展示最终判定卡片，阶段细节折叠。"""

    verdict = result.get("final_verdict", "?")
    confidence = result.get("final_confidence", 0)
    method = result.get("final_method", "?")
    llm_calls = result.get("_llm_calls", 0)

    if verdict == "vuln":
        verdict_text = "有漏洞"
    else:
        verdict_text = "安全"

    # Final verdict card — clean, minimal
    st.markdown(f"""
    <div style="
        background:#fff;border:1px solid #e8ecf0;border-radius:10px;
        padding:24px;margin:12px 0;text-align:center;
    ">
        <div style="font-size:12px;color:#999;letter-spacing:2px;margin-bottom:6px;">
            最终判定
        </div>
        <div style="font-size:40px;font-weight:700;color:#111;line-height:1.2;">
            {verdict_text}
        </div>
        <div style="margin-top:14px;display:flex;justify-content:center;gap:40px;">
            <div>
                <div style="font-size:11px;color:#999;">置信度</div>
                <div style="font-size:20px;font-weight:600;color:#111;">{confidence:.2f}</div>
            </div>
            <div>
                <div style="font-size:11px;color:#999;">方法</div>
                <div style="font-size:20px;font-weight:600;color:#111;">{method}</div>
            </div>
            <div>
                <div style="font-size:11px;color:#999;">LLM 调用</div>
                <div style="font-size:20px;font-weight:600;color:#111;">{llm_calls} 次</div>
            </div>
            <div>
                <div style="font-size:11px;color:#999;">耗时</div>
                <div style="font-size:20px;font-weight:600;color:#111;">{elapsed:.1f}s</div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Layer details — all collapsed
    _render_layer_details(result, elapsed)


def _render_layer_details(result: dict, elapsed: float) -> None:
    """渲染管道各层详情（全部折叠）。"""
    decision = result.get("_static_decision", "?")
    d_map = {
        "safe": "安全 -- 静态判定无风险",
        "vuln": "有漏洞 -- 静态已确认",
        "uncertain": "不确定 -- 提交 LLM 审查",
    }
    d_text = d_map.get(decision, str(decision))

    with st.expander("管道阶段详情", expanded=False):
        st.caption(f"第0层 静态决策: {d_text}")

        ctx = result.get("_context", {})
        if ctx:
            st.caption(
                f"第1层 代码窗口: Sink={ctx.get('sink','?')}  |  "
                f"类别={ctx.get('category','?')}  |  "
                f"风险={ctx.get('risk_level','?')}  |  "
                f"源变量={ctx.get('sources','?')}"
            )

        if "_tool_report_summary" in result:
            with st.expander("工具聚合报告 (Semgrep + CodeQL)", expanded=False):
                st.json(result["_tool_report_summary"])

        a1 = result.get("_agent1_parsed") or result.get("_agent1_raw")
        if a1 and isinstance(a1, dict):
            v = a1.get("verdict", "?")
            c = a1.get("confidence", 0)
            r = a1.get("reasoning", "?")
            st.caption(f"第2层 Agent1 筛查: 判定={v}  置信度={c:.2f}  推理={r[:120]}")

        voting = result.get("_voting_summary")
        if voting:
            vn = voting.get("vuln", 0)
            sn = voting.get("safe", 0)
            st.caption(f"第3层 Agent2 多温度投票: 漏洞={vn}  安全={sn}")
        else:
            a2 = result.get("_agent2_raw") or result.get("_agent2_parsed")
            if a2 and isinstance(a2, dict):
                st.caption(f"第3层 Agent2 验证: 判定={a2.get('verdict','?')}  置信度={a2.get('confidence',0):.2f}")

        a3 = result.get("_agent3_raw") or result.get("_agent3_parsed")
        if a3 and isinstance(a3, dict):
            st.caption(f"第4层 Agent3 证据: {str(a3)[:200]}")

        st.caption(
            f"LLM 调用: {result.get('_llm_calls', 0)} 次  |  "
            f"缓存命中: {result.get('_cache_hit', False)}  |  "
            f"总耗时: {elapsed:.1f}s"
        )
