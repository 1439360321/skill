"""Pluggable LLM call strategies: single_pass, agent_chain, multi_temp_voting."""
from __future__ import annotations

import json
import re
from src.utils.logger import setup_logger

logger = setup_logger()

# =========================================================================
# Prompt templates — all versions preserved
# =========================================================================

CWE_COT_PROMPTS: dict[str, str] = {
    "buffer_overflow": """Analyze this C code for BUFFER OVERFLOW (CWE-120/121/122).

CODE:
```c
{code_keyline}
```

Source: {sources}
Sanitizers: {sanitizers}
Dataflow: {dataflow}

Does user input reach a fixed-size buffer without proper bounds checking?
- If there's a strcpy/strcat/sprintf/memcpy into a fixed array without a verifiable bounds check → SUSPICIOUS
- If bounds are properly checked with sizeof() or a verified guard BEFORE the write → safe
- Only flag as suspicious if there is a clear, exploitable vulnerability path

Return raw JSON (no markdown):
{{"verdict":"suspicious/safe","confidence":0-1,"reasoning":"one sentence"}}""",

    "command_injection": """Analyze this code for COMMAND INJECTION (CWE-77/78).

CODE:
```{language}
{code_keyline}
```

Source: {sources} | Sanitizers: {sanitizers} | Dataflow: {dataflow}

Does user input flow into a shell command (system/popen/exec) without proper escaping?
When in doubt, flag as suspicious.

Return raw JSON (no markdown):
{{"verdict":"suspicious/safe","confidence":0-1,"reasoning":"one sentence"}}""",

    "code_injection": """Analyze this code for CODE INJECTION (CWE-94/95).

CODE:
```{language}
{code_keyline}
```

Source: {sources} | Sanitizers: {sanitizers} | Dataflow: {dataflow}

Does user input reach eval/exec/compile without proper validation?
When in doubt, flag as suspicious.

Return raw JSON (no markdown):
{{"verdict":"suspicious/safe","confidence":0-1,"reasoning":"one sentence"}}""",

    "sql_injection": """Analyze this code for SQL INJECTION (CWE-89).

CODE:
```{language}
{code_keyline}
```

Source: {sources} | Sanitizers: {sanitizers} | Dataflow: {dataflow}

Is user input concatenated into a SQL query without parameterized queries?
When in doubt, flag as suspicious.

Return raw JSON (no markdown):
{{"verdict":"suspicious/safe","confidence":0-1,"reasoning":"one sentence"}}""",

    "path_traversal": """Analyze this code for PATH TRAVERSAL (CWE-22).

CODE:
```{language}
{code_keyline}
```

Source: {sources} | Sanitizers: {sanitizers} | Dataflow: {dataflow}

Can user input escape the intended directory via ../ or absolute paths?
When in doubt, flag as suspicious.

Return raw JSON (no markdown):
{{"verdict":"suspicious/safe","confidence":0-1,"reasoning":"one sentence"}}""",

    "format_string": """Analyze this code for FORMAT STRING (CWE-134).

CODE:
```c
{code_keyline}
```

Source: {sources} | Sanitizers: {sanitizers} | Dataflow: {dataflow}

Is user input used as the format string argument to printf/fprintf/sprintf?
When in doubt, flag as suspicious.

Return raw JSON (no markdown):
{{"verdict":"suspicious/safe","confidence":0-1,"reasoning":"one sentence"}}""",

    "memory_corruption": """Analyze this code for MEMORY CORRUPTION (CWE-415/416).

CODE:
```c
{code_keyline}
```

Source: {sources} | Sanitizers: {sanitizers} | Dataflow: {dataflow}

Is there use-after-free, double-free, or NULL pointer dereference risk?
When in doubt, flag as suspicious.

Return raw JSON (no markdown):
{{"verdict":"suspicious/safe","confidence":0-1,"reasoning":"one sentence"}}""",

    "integer_overflow": """Analyze this code for INTEGER OVERFLOW (CWE-190).

CODE:
```c
{code_keyline}
```

Source: {sources} | Sanitizers: {sanitizers} | Dataflow: {dataflow}

Can user-controlled values overflow in malloc(size*count) or similar allocation?
When in doubt, flag as suspicious.

Return raw JSON (no markdown):
{{"verdict":"suspicious/safe","confidence":0-1,"reasoning":"one sentence"}}""",

    "deserialization": """Analyze this code for DESERIALIZATION (CWE-502).

CODE:
```{language}
{code_keyline}
```

Source: {sources} | Sanitizers: {sanitizers} | Dataflow: {dataflow}

Is untrusted data deserialized via pickle/yaml.load without safe loading?
When in doubt, flag as suspicious.

Return raw JSON (no markdown):
{{"verdict":"suspicious/safe","confidence":0-1,"reasoning":"one sentence"}}""",

    "race_condition": """Analyze this code for RACE CONDITION / TOCTOU (CWE-367).

CODE:
```c
{code_keyline}
```

Source: {sources} | Sanitizers: {sanitizers} | Dataflow: {dataflow}

Check pattern: access()/stat() check followed by open()/fopen() use.
Is there a time window where the filesystem state could change between check and use?
Also check for shared data accessed without locks/mutex/synchronization.

Return raw JSON (no markdown):
{{"verdict":"suspicious/safe","confidence":0-1,"reasoning":"one sentence"}}""",

    "generic": """Analyze this code for ANY security vulnerability (no specific CWE given).

CODE:
```{language}
{code_keyline}
```

Source: {sources} | Sanitizers: {sanitizers} | Dataflow: {dataflow}

No specific sink pattern was detected, but look for logic-level bugs:
- Array/pointer arithmetic: off-by-one, out-of-bounds?
- Memory: use-after-free, double-free, NULL deref?
- Integer: overflow in size calculations?
- Locking: missing unlock, double lock?
- Error paths: resource leak, uninitialized variable?

Be specific — reference exact lines. Only flag if you can identify a CONCRETE bug.

Return raw JSON (no markdown):
{{"verdict":"suspicious/safe","confidence":0-1,"reasoning":"one sentence citing specific line"}}""",
}

VERIFIER_PROMPT = """Re-examine this security finding against the CWE definition.

CWE category: {category}
Original analysis: {reasoning}
Static context: sink={sink}, source={sources}, sanitizers={sanitizers}, dataflow={dataflow}

CODE (focused on the sink):
```{language}
{code_keyline}
```

Compare the code against the CWE {category} definition:
1. Does the dataflow from source to sink match this CWE pattern?
2. Are sanitizers genuinely effective or trivially bypassable?
3. Is this a REAL vulnerability instance or a false pattern match?

IRIS rule: when in doubt, flag it. False negatives are worse than false positives.

Return raw JSON (no markdown):
{{"verdict":"vulnerable/safe","confidence":0-1,"reasoning":"CWE-context analysis"}}"""

VERIFIER_PROMPT_V4 = """Confirm or refute this vulnerability finding. A static analysis tool flagged a potential {category} at sink={sink}. Your job: determine if this is exploitable.

Verification focus: {reasoning}
Static context: sink={sink}, source={sources}, sanitizers={sanitizers}, dataflow={dataflow}

CODE:
```{language}
{code_keyline}
```

RULES (security-first — err on the side of caution):
1. Assume the sink IS reachable unless you see hard proof it isn't (e.g. dead code, #ifdef'd out)
2. Sanitizers are guilty until proven innocent — a sanitizer only counts if it handles ALL possible input values
3. sizeof() is NOT a sanitizer for variable-length data
4. A NULL check before use is NOT a sanitizer for buffer overflow
5. If user input could reach this sink through ANY indirect path → vulnerable
6. Only judge "safe" if you can articulate WHY the vulnerability is IMPOSSIBLE, not just unlikely

CONFIDENCE GUIDELINE:
- clear exploit path → 0.90-1.0
- likely exploitable, minor uncertainty → 0.80-0.89
- possible but uncertain → 0.65-0.79 (still VULNERABLE)
- safe only if provably unreachable or fully sanitized → 0.70-1.0

Return raw JSON (no markdown):
{{"verdict":"vulnerable/safe","confidence":0-1,"reasoning":"exploit analysis"}}"""

VERIFIER_PROMPT_V2 = """Re-examine this security finding.

Original analysis: {reasoning}
Static context: sink={sink}, source={sources}, sanitizers={sanitizers}, dataflow={dataflow}

FULL CODE:
```{language}
{code_keyline}
```

Look at the ACTUAL code carefully. Is the sanitization genuinely effective?
Could an attacker realistically bypass it? Is there a concrete exploit path?
When truly uncertain, better safe than sorry — flag it.

Return raw JSON (no markdown):
{{"verdict":"vulnerable/safe","confidence":0-1,"reasoning":"critical re-examination"}}"""

VERIFIER_PROMPT_V3 = """Re-examine this security finding.

Original analysis: {reasoning}
Static context: sink={sink}, source={sources}, sanitizers={sanitizers}, dataflow={dataflow}

FULL CODE:
```{language}
{code_keyline}
```

Look at the ACTUAL code carefully. Is the sanitization genuinely effective?
Could an attacker realistically bypass it? Is there a concrete exploit path?

JUDGMENT GUIDELINE: Your role is PRECISION — filter out false positives from the previous analysis.
Only confirm 'vulnerable' if you can articulate a CONCRETE exploit path.
When truly uncertain between safe and vulnerable, choose 'safe'.

Return raw JSON (no markdown):
{{"verdict":"vulnerable/safe","confidence":0-1,"reasoning":"critical re-examination"}}"""

FULL_SCAN_PROMPT = """You are a security code auditor. No sink was flagged -- the vulnerability (if any) is a logic bug, memory error, or concurrency issue. Check EACH category below. Do NOT judge safe unless ALL categories pass.

{rag_section}

FULL CODE:
```{language}
{code}
```

Static context: sink={sink}, sources={sources}, sanitizers={sanitizers}, dataflow={dataflow}

CHECK EACH CATEGORY (answer YES, NO, or UNCERTAIN):

1. MEMORY MANAGEMENT (UAF / double-free / leak):
   - Is a pointer freed then used later?
   - Is there a path where free() is called twice on the same pointer?
   - Is allocated memory leaked on an error/goto path?
   - Is a freed pointer still reachable through a container or list?

2. INTEGER OVERFLOW (CWE-190):
   - Is there multiplication before malloc/calloc, e.g. malloc(n * size)?
   - Can a loop counter overflow from signed/unsigned mismatch?
   - Is there unchecked addition in an index, offset, or allocation size?
   - Are there dangerous signed-to-unsigned or size_t conversions?

3. BOUNDARY / OFF-BY-ONE:
   - Does an array index check use < where it should use <=, or vice versa?
   - Does a loop iterate one too many or one too few times?
   - Is memcpy/memmove given a size from an untrusted or unvalidated source?

4. CONCURRENCY (race / deadlock):
   - Is shared state read or written without a visible lock?
   - Is there check-then-use (TOCTOU) on a shared resource?
   - Are global or static variables modified inside callbacks?

5. ERROR PATHS:
   - Does a goto/return skip cleanup, leaking a resource?
   - Is a pointer used after malloc returns NULL?
   - Is the return value of malloc, fopen, or similar ignored?

6. LOGIC BUGS:
   - Is a condition vacuously true or false in some edge case?
   - Is a switch missing a default case, or an if missing an else?
   - Can an array index or map key be negative, out of range, or missing?

RULES:
- If ANY category has YES or UNCERTAIN with a specific line: verdict = vulnerable
- Only return safe if ALL six categories are clearly NO
- Be specific: name the variable, the line, the exact condition

Return raw JSON (no markdown):
{{"verdict":"vulnerable/safe","confidence":0-1,"reasoning":"UAF=[answer] INT=[answer] BOUND=[answer] RACE=[answer] ERR=[answer] LOGIC=[answer]"}}"""

SINGLE_PASS_PROMPT = """You are a security code auditor. Analyze the following code for vulnerabilities.

CODE:
```{language}
{code}
```

Static analysis context:
- Sink functions detected: {sinks}
- Source variables (user input): {sources}
- Dataflow path: {dataflow}
- Sanitizers found: {sanitizers}
- Risk level: {risk_level}
- Sink category: {category}

INSTRUCTIONS:
1. Trace the dataflow: does user input reach a security-sensitive operation without effective validation?
2. Evaluate validation: are the detected sanitizers actually effective for THIS specific operation and dataflow?
3. Check for bypasses: could an attacker bypass validation with special characters, encoding, integer overflow, or race conditions?
4. Make a judgment: is there a concrete, exploitable vulnerability path?

JUDGMENT GUIDELINE: Flag as vulnerable if you can identify a concrete exploit path or a clear security flaw. For subtle issues (integer overflow, off-by-one, race conditions), flag if the flaw is technically exploitable under realistic conditions. When uncertain between safe and vulnerable, lean toward flagging the issue.

Output ONLY valid JSON (no markdown, no code blocks):
{{"has_vulnerability": true/false, "cwe_type": "CWE-XXX or empty", "confidence": 0.0-1.0, "reasoning": "2-3 sentence analysis", "line_numbers": [], "remediation": "suggested fix or empty"}}"""

BLIND_SPOT_PROMPT = """You are a blind-spot scanner. Agent2 already reviewed the code around sink={a2_focus} and judged: {a2_verdict}. Your job: find vulnerabilities OUTSIDE Agent2's focus area that A2 could not see.

{rag_section}

FULL CODE:
```{language}
{code}
```

Do NOT re-judge A2's focus area. Look ONLY at the rest of the code. Check EACH category (answer YES/NO/UNCERTAIN):

1. MEMORY: pointer freed then used later? double-free? leak on error path? freed pointer in container?
2. INTEGER: multiplication before malloc? loop counter overflow? unchecked addition? signed/unsigned issues?
3. BOUNDARY: wrong comparison? off-by-one loop? size from untrusted source?
4. CONCURRENCY: shared state without lock? TOCTOU? global modified in callback?
5. ERROR PATHS: goto/return skip cleanup? NULL deref after failed alloc? ignored return value?
6. LOGIC: condition vacuously true/false? missing else/default? index out of range?

If ANY category has YES/UNCERTAIN with specific line: return finding with confidence >= 0.8.
If nothing found: return {{"no_findings": true}}.
Do NOT say safe.

Return raw JSON (no markdown):
{{"has_vulnerability": true, "cwe_type": "CWE-XXX", "confidence": 0.85, "line_numbers": [start, end], "reasoning": "UAF=[answer] INT=[answer] BOUND=[answer] RACE=[answer] ERR=[answer] LOGIC=[answer]"}}
or
{{"no_findings": true}}"""


# =========================================================================
# JSON Parser
# =========================================================================

def parse_json(text: str, mode: str = "robust") -> dict | None:
    """Parse JSON from LLM response with configurable robustness."""
    if not text:
        return None

    cleaned = text.strip()
    cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
    cleaned = re.sub(r"\s*```\s*$", "", cleaned)
    # Fix DeepSeek V4 Flash quirk: stray quote after numeric values
    # {"confidence":1.0","reasoning":"..."} → {"confidence":1.0,"reasoning":"..."}
    # Must require decimal point to avoid matching digits in string values like "CWE-122"
    cleaned = re.sub(r'(\d+\.\d+)(",)', r'\1,', cleaned)
    cleaned = cleaned.strip()

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    if mode == "simple":
        m = re.search(r"\{[\s\S]*", cleaned)
        if m:
            open_b = m.group().count("{") - m.group().count("}")
            if open_b > 0:
                try:
                    return json.loads(m.group() + "}" * open_b)
                except json.JSONDecodeError:
                    pass
        return None

    # Robust mode: scan char by char to find last complete KV pair
    m = re.search(r"\{[\s\S]*", cleaned)
    if not m:
        logger.warning(f"JSON parse failed (no braces): {text[:100]}")
        return None

    json_str = m.group()
    try:
        return json.loads(json_str)
    except json.JSONDecodeError:
        pass

    # Walk through JSON tracking string boundaries and nesting depth.
    # Record the position after each complete top-level value (i.e. after each ',').
    depth = 0
    in_string = False
    last_complete = 1  # position right after '{'

    i = 1  # skip opening '{'
    while i < len(json_str):
        ch = json_str[i]
        if in_string:
            if ch == '\\':
                i += 2
                continue
            elif ch == '"':
                in_string = False
        else:
            if ch == '"':
                in_string = True
            elif ch in '{[':
                depth += 1
            elif ch in '}]':
                depth -= 1
            elif ch == ',' and depth == 0:
                last_complete = i
        i += 1

    truncated = json_str[:last_complete].rstrip(",").rstrip()
    if truncated.count('"') % 2 != 0:
        truncated += '"'

    missing = truncated.count("{") - truncated.count("}")
    if missing > 0:
        truncated += "}" * missing

    try:
        return json.loads(truncated)
    except json.JSONDecodeError:
        pass

    logger.warning(f"JSON parse failed: {text[:120]}")
    return None


# =========================================================================
# Helper functions
# =========================================================================

def _build_context(slice_data: dict) -> dict:
    """Extract structured context from slice_data."""
    code_patterns = slice_data.get("code_patterns", [])
    return {
        "function": slice_data.get("slicer_func_name") or slice_data.get("function_name", "?"),
        "sink": slice_data.get("sink_type", "?"),
        "category": slice_data.get("sink_category", "?"),
        "sources": slice_data.get("source_var", "unknown"),
        "sanitizers": slice_data.get("sanitization_detail", "").split("; ") if slice_data.get("sanitization_detail") else [],
        "dataflow": slice_data.get("dataflow_path", "?"),
        "language": slice_data.get("language", "c"),
        "code_patterns": [{"type": p.get("type",""), "desc": p.get("description","")} for p in code_patterns] if code_patterns else [],
    }


def _generic_screen_prompt(context: dict) -> str:
    return f"""Analyze this code for security issues.

CODE:
```{context.get('language', 'c')}
{context.get('code_keyline', context.get('code', '')[:1500])}
```
Sink: {context['sink']} ({context['category']})
Source: {context['sources']}
Sanitizers: {context['sanitizers']}
Dataflow: {context.get('dataflow', '?')}

When in doubt, flag as suspicious.
Return raw JSON: {{"verdict":"suspicious/safe","confidence":0-1,"reasoning":"short"}}"""


# =========================================================================
# Agent functions (used by agent_chain and multi_temp_voting)
# =========================================================================

def agent1_screen(client, context: dict, params: dict) -> dict | None:
    """Run CWE-specialized CoT prompt."""
    category = context.get("category", "")
    prompt_template = CWE_COT_PROMPTS.get(category)

    if not prompt_template:
        prompt = _generic_screen_prompt(context)
    else:
        sank_list = context.get("sanitizers", [])
        prompt = prompt_template.format(
            sources=context.get("sources", "unknown"),
            sanitizers=", ".join(sank_list) if sank_list else "none detected",
            code_keyline=context.get("code_keyline", "N/A"),
            dataflow=context.get("dataflow", "?"),
            language=context.get("language", "c"),
        )

    try:
        response = client.generate(prompt, system="Be concise. Return ONLY raw JSON.",
                                   temperature=params.get("agent1_temperature", 0.0),
                                   max_tokens=params.get("agent1_max_tokens", 2048))
        return parse_json(response, params.get("json_parser", "robust"))
    except Exception as e:
        logger.warning(f"Agent1 failed: {e}")
        return None


def agent2_verify(client, context: dict, agent1_result: dict, params: dict) -> dict:
    """Call Agent2 with configured prompt and temperature."""
    code_keyline = context.get("code_keyline",
        context.get("code", "")[:500] if context.get("code") else "N/A")
    sink = context.get("sink", "?")
    sources = context.get("sources", "?")
    sank = ", ".join(context.get("sanitizers", [])) or "none"
    df = context.get("dataflow", "?")
    lang = context.get("language", "c")
    category = context.get("category", "unknown")
    bias = params.get("agent2_bias", "flag_it")

    if bias == "precision":
        template = VERIFIER_PROMPT_V3
    elif bias == "flag_it":
        template = VERIFIER_PROMPT
    elif bias == "confirm_it":
        template = VERIFIER_PROMPT_V4
    else:
        template = VERIFIER_PROMPT_V2

    prompt = template.format(
        category=category,
        reasoning=agent1_result.get("verification_focus", agent1_result.get("reasoning", "")),
        sink=sink, sources=sources, sanitizers=sank, dataflow=df,
        language=lang, code_keyline=code_keyline,
    )

    try:
        resp = client.generate(prompt,
                               temperature=params.get("agent2_temperature", 0.1),
                               max_tokens=params.get("agent2_max_tokens", 1024))
        parsed = parse_json(resp, params.get("json_parser", "robust"))
        if parsed:
            verdict = parsed.get("verdict", "safe")
            return {
                "verdict": "confirmed_vuln" if verdict == "vulnerable" else "false_positive",
                "confidence": parsed.get("confidence", 0.5),
                "reasoning": parsed.get("reasoning", ""),
                "_raw_response": resp,
            }
    except Exception as e:
        logger.warning(f"Agent2 failed: {e}")

    return {"verdict": "uncertain", "confidence": 0.4}


def agent3_blind_spot(client, slice_data: dict, a2_result: dict, a2_focus: str,
                       params: dict, rag_context: str = "") -> dict | None:
    """Blind-spot scanner: find vulnerabilities OUTSIDE Agent2's reviewed area.

    Returns None if nothing found (NOT "safe" — just no findings).
    Returns dict with has_vulnerability=True if a blind-spot vuln is found.

    Args:
        rag_context: optional RAG-retrieved CVE knowledge for the vuln category.
    """
    code = slice_data.get("code", "")
    lang = slice_data.get("language", "c")

    a2_verdict = a2_result.get("verdict", "unknown") if a2_result else "unknown"
    if isinstance(a2_result, dict) and a2_result.get("has_vulnerability") is True:
        a2_verdict = "vulnerable"

    rag_section = ""
    if rag_context:
        rag_section = f"## Known Vulnerability Patterns (RAG)\nRelevant real-world CVEs:\n{rag_context}\n"

    prompt = BLIND_SPOT_PROMPT.format(
        a2_focus=str(a2_focus)[:200],
        a2_verdict=a2_verdict,
        rag_section=rag_section,
        language=lang,
        code=code,  # full code, not window
    )

    try:
        resp = client.generate(prompt,
                               temperature=params.get("agent3_temperature", 0.1),
                               max_tokens=params.get("agent3_max_tokens", 512))
        parsed = parse_json(resp, params.get("json_parser", "robust"))
        if parsed and parsed.get("no_findings"):
            return None
        if parsed and parsed.get("has_vulnerability"):
            return parsed
        return None
    except Exception as e:
        logger.warning(f"Agent3 blind-spot failed: {e}")
        return None


# =========================================================================
# Three LLM strategies
# =========================================================================

class SinglePassStrategy:
    """V7: One LLM call with structured output."""

    def __init__(self, client, params: dict):
        self.client = client
        self.params = params
        self.llm_calls = 0

    def analyze(self, slice_data: dict, context: dict, code_window: str) -> dict:
        lang = slice_data.get("language", "c")
        category = slice_data.get("sink_category", "unknown")
        risk = slice_data.get("risk_level", "medium")
        sank = slice_data.get("sanitization_detail", "none")
        df = slice_data.get("dataflow_path", "?")
        sink = slice_data.get("sink_type", "?")
        sources = slice_data.get("source_var", "unknown")

        prompt = SINGLE_PASS_PROMPT.format(
            code=code_window,
            language=lang,
            sinks=sink,
            sources=sources,
            dataflow=df,
            sanitizers=sank,
            risk_level=risk,
            category=category,
        )

        result = {}
        try:
            resp = self.client.generate(
                prompt,
                system="You are a precise security auditor. Return ONLY raw JSON.",
                temperature=self.params.get("single_pass_temperature", 0.3),
                max_tokens=self.params.get("single_pass_max_tokens", 2048),
            )
            parsed = parse_json(resp, self.params.get("json_parser", "robust"))
            self.llm_calls = 1
            result["_agent1_raw"] = resp
            result["_agent1_parsed"] = parsed

            if parsed:
                result["final_verdict"] = "vuln" if parsed.get("has_vulnerability") else "safe"
                result["final_method"] = "llm_single_pass"
                result["final_confidence"] = parsed.get("confidence", 0.5)
                result["vulnerability_type"] = parsed.get("cwe_type", "")
                result["llm_reasoning"] = parsed.get("reasoning", "")
                result["line_numbers"] = parsed.get("line_numbers", [])
                result["description"] = parsed.get("remediation", "")
                return result
        except Exception as e:
            logger.warning(f"Single-pass LLM failed: {e}")

        result["final_verdict"] = "vuln"
        result["final_method"] = "llm_parse_failure"
        result["final_confidence"] = 0.3
        return result


class AgentChainStrategy:
    """V1/V3: Agent1 screen → Agent2 verify (single-pass) → optional Agent3 evidence."""

    def __init__(self, client, params: dict):
        self.client = client
        self.params = params
        self.llm_calls = 0

    def analyze(self, slice_data: dict, context: dict, code_window: str) -> dict:
        context["code_keyline"] = code_window
        context["code"] = slice_data.get("code", "")
        result = {}

        # Agent1: screening
        a1 = agent1_screen(self.client, context, self.params)
        self.llm_calls += 1
        result["_agent1_raw"] = a1

        if not a1:
            result["final_verdict"] = "vuln"
            result["final_method"] = "llm_parse_failure"
            result["final_confidence"] = 0.3
            return result

        result["_agent1_parsed"] = a1

        if a1.get("verdict") != "suspicious":
            result["final_verdict"] = "safe"
            result["final_method"] = "llm_agent1_screened"
            result["final_confidence"] = a1.get("confidence", 0.3)
            result["llm_reasoning"] = a1.get("reasoning", "")
            return result

        # Agent2: verification (only if agent1 says suspicious)
        if self.params.get("agent2_enabled", True):
            a2 = agent2_verify(self.client, context, a1, self.params)
            self.llm_calls += 1
            result["_agent2_raw"] = a2

            if a2["verdict"] == "false_positive":
                result["final_verdict"] = "safe"
                result["final_method"] = "llm_agent2_false_positive"
                result["final_confidence"] = a2.get("confidence", 0.3)
                result["llm_reasoning"] = a1.get("reasoning", "")
                # A2=safe → trigger A3 blind-spot scan
                if self.params.get("agent3_enabled", False):
                    self._run_a3(slice_data, result, a2, code_window)
                return result

            elif a2["verdict"] == "uncertain":
                result["final_verdict"] = "vuln"
                result["final_method"] = "llm_agent2_uncertain"
                result["final_confidence"] = 0.5
                result["llm_reasoning"] = a1.get("reasoning", "")
                # A2=uncertain → trigger A3 blind-spot scan
                if self.params.get("agent3_enabled", False):
                    self._run_a3(slice_data, result, a2, code_window)
                return result

            # confirmed_vuln → A2 high confidence, skip A3
            result["final_verdict"] = "vuln"
            result["final_method"] = "llm_full_pipeline"
            result["final_confidence"] = a2.get("confidence", 0.8)
            result["llm_reasoning"] = a1.get("reasoning", "")
            return result

        else:
            # No agent2 — agent1 suspicious = vuln
            result["final_verdict"] = "vuln"
            result["final_method"] = "llm_agent1_only"
            result["final_confidence"] = a1.get("confidence", 0.5)
            result["llm_reasoning"] = a1.get("reasoning", "")
            return result

    def _run_a3(self, slice_data: dict, result: dict, a2: dict, code_window: str) -> None:
        """Run Agent3 blind-spot scanner and potentially overturn A2's safe verdict.

        Accepts A3 findings at ≥0.7 confidence (lower bar than generic 0.8 —
        A3 is looking at code A2 literally couldn't see, so its evidence
        should be trusted more readily). ConfidenceCalibrator in post_process
        further refines based on whether A3's finding is independent (blind spot)
        or overlapping (re-evaluating A2's area).
        """
        a3 = agent3_blind_spot(self.client, slice_data, a2, code_window, self.params)
        self.llm_calls += 1

        if a3 is None:
            # No blind-spot findings — A2's verdict stands
            return

        # A3 found a vulnerability A2 missed
        result["_agent3_raw"] = a3
        a3_conf = a3.get("confidence", 0.5)

        if a3_conf >= 0.7:
            result["final_verdict"] = "vuln"
            result["final_method"] = result.get("final_method", "") + "_a3_blind_spot"
            result["final_confidence"] = a3_conf
            result["vulnerability_type"] = a3.get("cwe_type", "CWE-UNKNOWN")
            result["line_numbers"] = a3.get("line_numbers", [])
            result["llm_reasoning"] = (result.get("llm_reasoning", "") +
                                       f" [A3 BLIND SPOT: {a3.get('reasoning', '')}]")


class MultiTempVotingStrategy:
    """V2: Agent1 screen → Agent2 with multi-temperature weighted voting → optional Agent3."""

    def __init__(self, client, params: dict):
        self.client = client
        self.params = params
        self.llm_calls = 0

    def analyze(self, slice_data: dict, context: dict, code_window: str) -> dict:
        context["code_keyline"] = code_window
        context["code"] = slice_data.get("code", "")
        result = {}

        # Agent1: screening
        a1 = agent1_screen(self.client, context, self.params)
        self.llm_calls += 1
        result["_agent1_raw"] = a1

        if not a1:
            result["final_verdict"] = "vuln"
            result["final_method"] = "llm_parse_failure"
            result["final_confidence"] = 0.3
            return result

        result["_agent1_parsed"] = a1

        if a1.get("verdict") != "suspicious":
            result["final_verdict"] = "safe"
            result["final_method"] = "llm_agent1_screened"
            result["final_confidence"] = a1.get("confidence", 0.3)
            result["llm_reasoning"] = a1.get("reasoning", "")
            return result

        # Agent2: multi-temperature voting
        temps = self.params.get("voting_temperatures", [0.0, 0.3, 0.7])
        weights = self.params.get("voting_weights", {})

        code_keyline = context.get("code_keyline",
            context.get("code", "")[:500] if context.get("code") else "N/A")
        sink = context.get("sink", "?")
        sources = context.get("sources", "?")
        sank = ", ".join(context.get("sanitizers", [])) or "none"
        df = context.get("dataflow", "?")
        lang = context.get("language", "c")
        category = context.get("category", "unknown")

        prompt = VERIFIER_PROMPT_V2.format(
            category=category,
            reasoning=a1.get("reasoning", ""),
            sink=sink, sources=sources, sanitizers=sank, dataflow=df,
            language=lang, code_keyline=code_keyline,
        )

        votes: list[tuple[float, str]] = []
        for temp in temps:
            try:
                resp = self.client.generate(prompt,
                                            temperature=temp,
                                            max_tokens=self.params.get("agent2_max_tokens", 2048))
                self.llm_calls += 1
                parsed = parse_json(resp, self.params.get("json_parser", "robust"))
                if parsed:
                    verdict = parsed.get("verdict", "safe")
                    votes.append((temp, verdict))
                    result.setdefault("_agent2_raws", {})[str(temp)] = {"verdict": verdict, "_resp": resp[:200] if resp else ""}
            except Exception as e:
                logger.warning(f"Agent2 vote failed (temp={temp}): {e}")

        # Tally votes
        vuln_score = sum(weights.get(str(t), 1.0) for t, v in votes if v == "vulnerable")
        safe_score = sum(weights.get(str(t), 1.0) for t, v in votes if v == "safe")
        vuln_count = sum(1 for _, v in votes if v == "vulnerable")
        safe_count = len(votes) - vuln_count
        consensus = self.params.get("voting_consensus", 2)

        if len(votes) == 0:
            result["final_verdict"] = "vuln"  # fail conservative
            result["final_method"] = "llm_voting_no_votes"
            result["final_confidence"] = 0.4
        elif vuln_count >= consensus:
            result["final_verdict"] = "vuln"
            result["final_method"] = "llm_voting_confirmed"
            result["final_confidence"] = a1.get("confidence", 0.5) if weights else 0.7
        elif vuln_score >= 1.5 and vuln_score > safe_score:
            result["final_verdict"] = "vuln"
            result["final_method"] = "llm_voting_weighted"
            result["final_confidence"] = 0.6
        elif safe_score >= 1.5 or vuln_score < 0.5:
            result["final_verdict"] = "safe"
            result["final_method"] = "llm_voting_false_positive"
            result["final_confidence"] = 0.3
        else:
            result["final_verdict"] = "vuln"  # uncertain → conservative
            result["final_method"] = "llm_voting_uncertain"
            result["final_confidence"] = 0.5

        result["_voting_summary"] = {"vuln": vuln_count, "safe": safe_count,
                                     "vuln_score": vuln_score, "safe_score": safe_score}

        result["llm_reasoning"] = a1.get("reasoning", "")
        return result


# =========================================================================
# Tool-Aware Agent1 prompt — reads tool reports, NOT code
# =========================================================================

TOOL_INTEGRATOR_PROMPT = """You are a static analysis tool integrator. Your job is to read the OUTPUT of multiple static analysis tools and decide the investigation strategy. You do NOT read source code — you only read tool reports.

## Tool Results

{language} code, {code_len} chars, function: {func_name}

### CodeSlicer (pattern-based sink detection)
Sink: {sink} ({sink_category})
Risk: {risk_level}
Sanitization: {sanitization}
Sources: {sources}
Dataflow: {dataflow}

### All Tool Findings
{findings_summary}

### Tool Consensus
Level: {consensus_level}
{consensus_detail}

### Tool Coverage & Blind Spots
Tools that ran: {tools_run}
Tools that failed: {tools_failed}
Areas NO tool checked: {blind_spots}

## Your Task

Based on the tool signals above, decide the investigation strategy:

1. **Initial screening**: suspicious or safe? When any tool finds a sink → suspicious.
2. **Window strategy**:
   - "iris" — tools agree on a specific line → Agent2 only needs ±5 lines around it
   - "medium" — one tool found a sink → Agent2 needs the code AROUND that sink (±15 lines)
   - "full" — tools found nothing → Agent2 needs the complete function
3. **Blind spot risk**:
   - "high" — memory safety / logic areas uncovered → MUST run Agent3
   - "medium" — some areas uncovered → run Agent3 if Agent2 says safe
   - "low" — tools cover most categories → skip Agent3 unless Agent2 uncertain
4. **Verification focus** — what Agent2 should specifically check (sink behavior, bypass potential, dataflow path). Be precise and directive. Do NOT say "weak signal" or pre-judge — your job is to point A2 at the target, not to predict the outcome.

## Decision Rules
- Any tool found a sink → suspicious. Send to A2 for verification.
- Multiple tools flagging same area → narrow window, high confidence
- Tools silent → full review needed
- Sanitization reported? → Tell A2 to verify if sanitizers are bypassable. Do NOT assume they work.

Return raw JSON (no markdown):
{{"initial_verdict": "suspicious"|"safe", "confidence": 0.0-1.0, "window_suggestion": "iris"|"medium"|"full", "blind_spot_risk": "high"|"medium"|"low", "reasoning": "brief"}}"""


def agent1_integrate(client, tool_report: dict, params: dict) -> dict | None:
    """Agent1: tool integrator — reads tool reports only, does NOT read code."""
    findings_lines = []
    for f in tool_report.get("findings", []):
        findings_lines.append(
            f"  [{f['tool']}] {f['type']} @ line {f.get('line', '?')}: {f.get('message', '')[:120]}"
        )
    findings_summary = "\n".join(findings_lines) if findings_lines else "  (no findings)"

    blind_spots = tool_report.get("blind_spots", [])
    if not blind_spots:
        blind_spots = ["(all major categories covered by at least one tool)"]

    prompt = TOOL_INTEGRATOR_PROMPT.format(
        language=tool_report.get("language", "c"),
        code_len=tool_report.get("_code_len", "?"),
        func_name=tool_report.get("_func_name", "?"),
        sink=tool_report.get("sink", "none"),
        sink_category=tool_report.get("sink_category", "generic"),
        risk_level=tool_report.get("risk_level", "low"),
        sanitization="yes — " + tool_report.get("sanitization_detail", "")
                      if tool_report.get("has_sanitization") else "none detected",
        sources=tool_report.get("_sources", "unknown"),
        dataflow=tool_report.get("_dataflow", "?"),
        findings_summary=findings_summary,
        consensus_level=tool_report.get("consensus", {}).get("level", "no_signal"),
        consensus_detail=tool_report.get("consensus", {}).get("detail", ""),
        tools_run=", ".join(tool_report.get("tools_run", ["codeslicer"])),
        tools_failed=", ".join(tool_report.get("tools_failed", [])) or "none",
        blind_spots=", ".join(blind_spots),
    )

    try:
        response = client.generate(prompt,
                                   temperature=params.get("agent1_temperature", 0.0),
                                   max_tokens=params.get("agent1_max_tokens", 1024))
        return parse_json(response, params.get("json_parser", "robust"))
    except Exception as e:
        logger.warning(f"Agent1 (tool integrator) failed: {e}")
        return None


class ToolAwareChainStrategy:
    """Agent1 integrates tool results → Agent2 verifies → A3 blind-spot (or merged when full window).

    Architecture:
      A1 (tool integrator): reads tool reports, decides window + blind spot risk
      A2 (focused verifier): reviews code at A1-suggested window
        - iris/medium window → focused prompt, no RAG (verify specific finding)
        - full window → FULL_SCAN_PROMPT + RAG (comprehensive scan, A3 merged in)
      A3 (blind-spot scanner): only when window != full (A2 missed unseen code)
    """

    def __init__(self, client, params: dict):
        self.client = client
        self.params = params
        self.llm_calls = 0

    def analyze(self, slice_data: dict, context: dict, code_window: str) -> dict:
        result: dict = {}

        # Build tool report (passed in via slice_data or built here)
        tool_report = slice_data.get("_tool_report", {})
        if not tool_report:
            tool_report = self._build_minimal_report(slice_data, context)

        # --- A1: Tool integrator ---
        a1 = agent1_integrate(self.client, tool_report, self.params)
        self.llm_calls += 1
        result["_agent1_raw"] = a1
        result["_tool_report"] = tool_report

        if not a1:
            result["final_verdict"] = "vuln"
            result["final_method"] = "tool_aware_a1_failed"
            result["final_confidence"] = 0.3
            return result

        result["_agent1_parsed"] = a1
        window_suggestion = a1.get("window_suggestion", "full")
        result["_window_suggestion"] = window_suggestion

        if a1.get("initial_verdict") != "suspicious":
            result["final_verdict"] = "safe"
            result["final_method"] = "tool_aware_a1_screened"
            result["final_confidence"] = a1.get("confidence", 0.3)
            result["llm_reasoning"] = a1.get("reasoning", "")
            if a1.get("blind_spot_risk") in ("high", "medium"):
                if window_suggestion == "full":
                    self._run_a2_full_scan(slice_data, context, result, a1, code_window)
                else:
                    self._run_a3_with_rag(slice_data, result, a1, code_window)
            return result

        # --- A2: verification or full scan ---
        if window_suggestion == "full":
            # Tools silent → A2 gets full code + RAG, A3 merged in (skip A3)
            self._run_a2_full_scan(slice_data, context, result, a1, code_window)
            return result

        # iris / medium window → focused verify, keep A3 separate
        dynamic_window = self._extract_dynamic_window(slice_data, context, code_window, window_suggestion)
        context["code_keyline"] = dynamic_window
        context["code"] = slice_data.get("code", "")

        # Agent2: single call or multi-temp weighted voting
        agent2_temps = self.params.get("agent2_temperatures", None)
        if agent2_temps and isinstance(agent2_temps, list) and len(agent2_temps) >= 2:
            a2 = self._run_a2_multi_temp(context, a1, agent2_temps)
        else:
            a2 = agent2_verify(self.client, context, a1, self.params)
            self.llm_calls += 1
        result["_agent2_raw"] = a2

        if a2["verdict"] == "false_positive":
            result["final_verdict"] = "safe"
            result["final_method"] = "tool_aware_a2_false_positive"
            result["final_confidence"] = a2.get("confidence", 0.3)
            result["llm_reasoning"] = a1.get("reasoning", "")
            if self.params.get("agent3_enabled", True):
                self._run_a3_with_rag(slice_data, result, a1, code_window)
            return result

        elif a2["verdict"] == "uncertain":
            result["final_verdict"] = "vuln"
            result["final_method"] = "tool_aware_a2_uncertain"
            result["final_confidence"] = 0.5
            result["llm_reasoning"] = a1.get("reasoning", "")
            if self.params.get("agent3_enabled", True):
                self._run_a3_with_rag(slice_data, result, a1, code_window)
            return result

        # A2 confirmed vuln
        result["final_verdict"] = "vuln"
        result["final_method"] = "tool_aware_full_pipeline"
        result["final_confidence"] = a2.get("confidence", 0.8)
        result["llm_reasoning"] = a1.get("reasoning", "")

        if a1.get("blind_spot_risk") == "high":
            self._run_a3_with_rag(slice_data, result, a1, code_window)

        return result

    def _run_a2_full_scan(self, slice_data: dict, context: dict,
                           result: dict, a1: dict, code_window: str) -> None:
        """Merged A2+A3: full code + RAG → comprehensive scan in one call."""
        code = slice_data.get("code", "")
        lang = slice_data.get("language", "c")
        sink = context.get("sink", "none")
        sources = context.get("sources", "unknown")
        sanitizers = ", ".join(context.get("sanitizers", [])) or "none"
        dataflow = context.get("dataflow", "?")

        rag_context = self._query_rag(slice_data, result, a1)
        rag_section = ""
        if rag_context:
            rag_section = f"## Known Vulnerability Patterns (RAG)\nRelevant real-world CVEs:\n{rag_context}\n"

        prompt = FULL_SCAN_PROMPT.format(
            rag_section=rag_section,
            language=lang,
            code=code,
            sink=sink,
            sources=sources,
            sanitizers=sanitizers,
            dataflow=dataflow,
        )

        try:
            resp = self.client.generate(prompt,
                                        temperature=self.params.get("agent2_temperature", 0.1),
                                        max_tokens=self.params.get("agent2_max_tokens", 2048))
            parsed = parse_json(resp, self.params.get("json_parser", "robust"))
        except Exception:
            parsed = None

        self.llm_calls += 1
        result["_agent2_raw"] = parsed or {}
        result["_rag_context"] = rag_context

        if not parsed:
            result["final_verdict"] = "vuln"
            result["final_method"] = "tool_aware_full_scan_parse_failed"
            result["final_confidence"] = 0.3
            return

        verdict = parsed.get("verdict", "")
        if verdict == "vulnerable":
            result["final_verdict"] = "vuln"
            result["final_method"] = "tool_aware_full_scan_vuln"
            result["final_confidence"] = parsed.get("confidence", 0.7)
        else:
            result["final_verdict"] = "safe"
            result["final_method"] = "tool_aware_full_scan_safe"
            result["final_confidence"] = parsed.get("confidence", 0.5)

        result["llm_reasoning"] = parsed.get("reasoning", "")
        # No A3 — already covered in this full scan

    def _extract_dynamic_window(self, slice_data: dict, context: dict,
                                 full_window: str, suggestion: str) -> str:
        """Extract code window based on A1's suggestion.

        Only "iris" truncates (strong tool signal, narrow focus saves tokens).
        "medium" and "full" both receive the complete code.
        """
        code = slice_data.get("code", "")
        sink_type = slice_data.get("sink_type", "")

        if suggestion == "iris" and sink_type:
            # Extract ±5 lines around the sink line
            lines = code.split("\n")
            sink_line = slice_data.get("line_start", 0)
            window_lines = self.params.get("dynamic_iris_lines", 5)
            max_chars = self.params.get("iris_max_chars", 3000)
            start = max(0, sink_line - 1 - window_lines)
            end = min(len(lines), sink_line + window_lines)
            window = "\n".join(lines[start:end])
            if len(window) > max_chars:
                window = window[:max_chars] + "\n// ... (truncated)"
            return window

        # medium / full: give A2 everything, let it decide what matters
        return code

    def _run_a2_multi_temp(self, context: dict, a1: dict,
                           temperatures: list) -> dict:
        """Agent2 multi-temperature weighted vote.

        Uses flag_it bias (conservative base) so temperature changes
        produce real divergence. Each verdict weighted by confidence.
        vuln_weight / total_weight >= threshold → confirmed_vuln.
        """
        import copy
        vuln_weight = 0.0
        total_weight = 0.0
        results = []
        threshold = self.params.get("voting_threshold", 0.5)

        for temp in temperatures:
            p = copy.deepcopy(self.params)
            p["agent2_temperature"] = temp
            p["agent2_bias"] = "flag_it"  # conservative base → temperature matters
            a2 = agent2_verify(self.client, context, a1, p)
            self.llm_calls += 1
            results.append(a2)

            conf = a2.get("confidence", 0.5)
            total_weight += conf
            if a2["verdict"] == "confirmed_vuln":
                vuln_weight += conf

        best = max(results, key=lambda r: r.get("confidence", 0))
        temps_str = ','.join(str(t) for t in temperatures)

        if total_weight > 0 and (vuln_weight / total_weight) >= threshold:
            return {
                "verdict": "confirmed_vuln",
                "confidence": best.get("confidence", 0.7),
                "reasoning": f"multi-temp({temps_str}): "
                             f"{vuln_weight:.2f}/{total_weight:.2f}≥{threshold}"
            }
        return {
            "verdict": "false_positive",
            "confidence": best.get("confidence", 0.5),
            "reasoning": f"multi-temp({temps_str}): "
                         f"{vuln_weight:.2f}/{total_weight:.2f}<{threshold}"
        }

    def _run_a3_with_rag(self, slice_data: dict, result: dict,
                          a1: dict, code_window: str) -> None:
        """Run A3 blind-spot scanner with RAG augmentation."""
        # Query RAG for relevant CVE knowledge
        rag_context = self._query_rag(slice_data, result, a1)

        a3 = agent3_blind_spot(self.client, slice_data,
                                result.get("_agent2_raw", {}),
                                code_window, self.params,
                                rag_context=rag_context)
        self.llm_calls += 1

        if a3 is None:
            return

        result["_agent3_raw"] = a3
        result["_rag_context"] = rag_context
        a3_conf = a3.get("confidence", 0.5)

        if a3_conf >= 0.7:
            result["final_verdict"] = "vuln"
            result["final_method"] = result.get("final_method", "") + "_a3_blind_spot"
            result["final_confidence"] = a3_conf
            result["vulnerability_type"] = a3.get("cwe_type", "CWE-UNKNOWN")
            result["line_numbers"] = a3.get("line_numbers", [])
            result["llm_reasoning"] = (result.get("llm_reasoning", "") +
                                       f" [A3 BLIND SPOT: {a3.get('reasoning', '')}]")

    def _query_rag(self, slice_data: dict, result: dict, a1: dict) -> str:
        """Query vector store for relevant vulnerability knowledge."""
        if not self.params.get("enable_rag", True):
            return ""
        try:
            from src.rag.vector_store import VectorStore
            vs = VectorStore()
            if vs.count() == 0:
                return ""

            # Build query from blind spots + CWE focus + sink context
            blind_spots = a1.get("blind_spot_risk", "")
            fc = a1.get("focus_cwe", "")
            focus_cwes = fc if isinstance(fc, str) else ", ".join(fc) if fc else ""
            sink_cat = slice_data.get("sink_category", "")
            query_parts = [f"C {sink_cat} vulnerability"]
            if focus_cwes:
                query_parts.append(focus_cwes)
            if blind_spots:
                query_parts.append(f"blind spot {blind_spots} risk")

            query = " ".join(query_parts)
            results = vs.query(query, top_k=3, similarity_threshold=0.35)

            if not results:
                return ""

            lines = []
            for r in results:
                meta = r.get("metadata", {})
                cwe = meta.get("cwe_id", "")
                desc = r.get("document", "")[:300]
                lines.append(f"CWE-{cwe}: {desc}")
            return "\n".join(lines)
        except Exception as e:
            logger.warning(f"RAG query failed: {e}")
            return ""

    @staticmethod
    def _build_minimal_report(slice_data: dict, context: dict) -> dict:
        """Fallback: build tool report from CodeSlicer data alone."""
        from src.scanner.tool_aggregator import aggregate
        return aggregate(slice_data, slice_data.get("language", "c"))


def create_llm_strategy(client, params: dict):
    """Factory: return strategy instance based on llm.mode."""
    mode = params.get("mode", "agent_chain")
    if mode == "single_pass":
        return SinglePassStrategy(client, params)
    elif mode == "multi_temp_voting":
        return MultiTempVotingStrategy(client, params)
    elif mode == "tool_aware_chain":
        return ToolAwareChainStrategy(client, params)
    return AgentChainStrategy(client, params)
