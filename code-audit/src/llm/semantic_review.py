"""Semantic code review with LLM — multi-strategy prompt system.

Supports 5 prompt strategies for ablation comparison:

1. **baseline** — current NO_SINK + BORDERLINE, strict FP filtering
2. **cot** — Chain-of-Thought: step-by-step reasoning before verdict
3. **cwe_specialized** — different prompt per CWE category
4. **adversarial** — LLM argues both sides, then decides
5. **strict** — ultra-conservative: only flag when 100% certain

Usage:
    reviewer = SemanticReviewer(strategy="cot")
    finding = reviewer.review_no_sink_file(code, "c")
    verified = reviewer.verify_borderline(slice_data)
    verified = reviewer.verify_all(slice_data)  # verify even high-risk
"""

from __future__ import annotations

from src.llm.ollama_client import OllamaClient
from src.llm.parser import LLMOutputParser
from src.utils.logger import setup_logger

logger = setup_logger()

# ---------------------------------------------------------------------------
# Prompt: No-sink semantic review
# ---------------------------------------------------------------------------

NO_SINK_SYSTEM = """You are a precise code security auditor. Find CONCRETE logic bugs in code that a pattern-matcher would miss. Rules: 1) Only report PROVABLE flaws with specific line. 2) Guards (null check, bounds check, size limit) → SAFE. 3) <90% certain → safe. Be SHORT."""

NO_SINK_PROMPT = """Find logic bugs (off-by-one, null deref, unbounded copy, integer overflow) in this {language} code. Only report PROVABLE flaws. Guards (null checks, bounds) → SAFE.

【Code】```{language}
{code}
```
Return ONLY raw JSON (no markdown):
{{"has_vulnerability": bool, "vulnerability_type": "CWE-XXX or NONE", "confidence": 0.0-1.0, "severity": "HIGH/MEDIUM/LOW/INFO", "description": "short"}}"""


# ---------------------------------------------------------------------------
# Prompt: Borderline verification
# ---------------------------------------------------------------------------

BORDERLINE_SYSTEM = """You are a code security auditor reviewing a borderline case flagged
by static analysis. The static analyzer found a potentially dangerous function call
but is uncertain whether it is actually exploitable due to sanitization or context.

Your job: determine if this is a REAL vulnerability or a FALSE POSITIVE.

Be CONCISE and DECISIVE. Don't hedge — give a clear yes/no with reasoning.
deepseek-r1: keep your <think> block under 200 words."""

BORDERLINE_PROMPT = """Verify whether this code contains a REAL exploitable vulnerability.

【Static Analysis Summary】
- Language: {language}
- Suspicious function (sink): {sink_type}
- Vulnerability category: {sink_category}
- Risk assessment: {risk_level}
- Sanitization detected: {sanitization_detail}
- Data flow: {dataflow_path}

【Code】
```{language}
{code}
```

Check carefully:
1. Is the suspicious function ACTUALLY called with attacker-controllable input?
2. Is the sanitization/validation SUFFICIENT? Can it be bypassed?
3. What is the REAL-WORLD impact if exploited?

CRITICAL: If the code uses safe wrappers, length checks, allowlists, or other
protections that GENUINELY prevent exploitation, mark has_vulnerability: false.

Return ONLY raw JSON (no markdown, no ```):
{{
  "has_vulnerability": true or false,
  "vulnerability_type": "CWE-XXX or NONE",
  "confidence": 0.0 to 1.0,
  "severity": "HIGH/MEDIUM/LOW/INFO",
  "description": "one sentence",
  "reasoning": "brief justification — why is this real or false positive?"
}}"""


# ---------------------------------------------------------------------------
# Prompt: Full-file semantic sweep
# ---------------------------------------------------------------------------

FULL_FILE_SYSTEM = """You are a code security auditor. Review this complete source file and
identify ALL security vulnerabilities — both those involving standard library calls
AND logic-level bugs (off-by-one, null deref, integer issues, race conditions).

This is a CATCH-ALL review. The static analyzer may have missed something.
Be thorough but don't fabricate issues. Only report REAL, exploitable problems."""

FULL_FILE_PROMPT = """Review this complete {language} source file for security vulnerabilities.

Context: This file was scanned by pattern-based static analysis. We need a second
opinion to catch anything the pattern matcher may have missed.

【Full Source File】
```{language}
{code}
```

Identify ALL vulnerabilities:
1. Standard library misuse (strcpy, system, gets, etc.)
2. Logic bugs (off-by-one, null deref, integer issues)
3. Missing input validation
4. Race conditions (TOCTOU)

For EACH vulnerability found, include:
- Function name
- CWE ID
- Brief description
- Confidence score

If the file is COMPLETELY SAFE, return an empty list.

Return ONLY this JSON:
{{
  "findings": [
    {{
      "has_vulnerability": true,
      "function_name": "function name",
      "vulnerability_type": "CWE-XXX",
      "confidence": 0.0 to 1.0,
      "severity": "HIGH/MEDIUM/LOW/INFO",
      "description": "one sentence",
      "line_numbers": [start, end]
    }}
  ]
}}"""


# ===========================================================================
# Strategy 2: Chain-of-Thought (CoT)
# ===========================================================================

COT_SYSTEM = """You are a senior security auditor. For each code sample,
think STEP BY STEP before reaching a conclusion. Structure your reasoning:

STEP 1 — Identify the dangerous operation (which function call is the sink?)
STEP 2 — Trace the data source (does user input ACTUALLY reach this sink?)
STEP 3 — Check protections (is there sanitization/validation BEFORE the sink?)
STEP 4 — Assess exploitability (can an attacker realistically exploit this?)
STEP 5 — Final verdict with confidence.

CRITICAL RULES:
- If Step 2 fails (no user input path) → SAFE
- If Step 3 passes (good sanitization) → SAFE
- If Step 4 fails (not exploitable in practice) → SAFE
- Only mark VULNERABLE when ALL 4 checks confirm it."""

COT_PROMPT = """Analyze this {language} code step by step, then give your verdict.

【Code】
```{language}
{code}
```
{sink_context}

Reason through each step:
STEP 1 — Dangerous operation:
STEP 2 — Data source trace:
STEP 3 — Protection check:
STEP 4 — Exploitability:
STEP 5 — Final verdict:

Return ONLY raw JSON after your reasoning (no markdown, no ```):
{{
  "has_vulnerability": true or false,
  "vulnerability_type": "CWE-XXX or NONE",
  "confidence": 0.0 to 1.0,
  "severity": "HIGH/MEDIUM/LOW/INFO",
  "description": "one sentence summary"
}}"""


# ===========================================================================
# Strategy 3: CWE-Specialized
# ===========================================================================

CWE_PROMPTS: dict[str, str] = {
    "buffer_overflow": """You are checking for BUFFER OVERFLOW (CWE-119/120/121/122).

Key question: Does data copy into a fixed-size buffer WITH a size check?

BUFFER OVERFLOW = YES when:
- strcpy/strcat/memcpy/gets used WITHOUT checking input length against buffer size
- sprintf used without format width specifiers
- manual copy loop with i<=n (off-by-one)

SAFE when:
- strncpy/strncat/snprintf with correct size
- strlen(input) < sizeof(buf) check BEFORE copy
- fgets with sizeof(buf)
- memcpy with sizeof(dest) or bounded size

The code you are reviewing:
```{language}
{code}
```

Return ONLY JSON:
{{"has_vulnerability": bool, "vulnerability_type": "CWE-120 or NONE", "confidence": 0.0-1.0, "severity": "HIGH/MEDIUM/LOW/INFO", "description": "..."}}""",

    "command_injection": """You are checking for COMMAND INJECTION (CWE-77/78).

Key question: Is user input concatenated into a shell command string?

COMMAND INJECTION = YES when:
- system()/popen() receives user-controlled string
- subprocess with shell=True and user input in command string
- exec*() family with user-controlled arguments

SAFE when:
- Hardcoded command with fixed arguments
- subprocess with list args (not shell=True)
- shlex.quote() or pipes.quote() applied to user input
- Whitelist validation of allowed commands

The code you are reviewing:
```{language}
{code}
```

Return ONLY JSON:
{{"has_vulnerability": bool, "vulnerability_type": "CWE-78 or NONE", "confidence": 0.0-1.0, "severity": "HIGH/MEDIUM/LOW/INFO", "description": "..."}}""",

    "code_injection": """You are checking for CODE INJECTION (CWE-94/95).

Key question: Is user input passed to eval/exec/compile?

CODE INJECTION = YES when:
- eval() or exec() receives user-controlled string
- compile() with user input as code
- __import__() or importlib with user-controlled module name

SAFE when:
- ast.literal_eval() instead of eval()
- Restricted __builtins__ in exec context
- Input validated against strict allowlist before eval

The code you are reviewing:
```{language}
{code}
```

Return ONLY JSON:
{{"has_vulnerability": bool, "vulnerability_type": "CWE-94 or NONE", "confidence": 0.0-1.0, "severity": "HIGH/MEDIUM/LOW/INFO", "description": "..."}}""",

    "sql_injection": """You are checking for SQL INJECTION (CWE-89).

Key question: Is user input concatenated into SQL query string?

SQL INJECTION = YES when:
- f-string or + concatenation builds SQL with user values
- .format() with user input in SQL
- Raw SQL execution without parameter binding

SAFE when:
- Parameterized queries (cursor.execute(query, (param,)))
- PreparedStatement (Java)
- ORM with proper parameter binding

The code you are reviewing:
```{language}
{code}
```

Return ONLY JSON:
{{"has_vulnerability": bool, "vulnerability_type": "CWE-89 or NONE", "confidence": 0.0-1.0, "severity": "HIGH/MEDIUM/LOW/INFO", "description": "..."}}""",

    "path_traversal": """You are checking for PATH TRAVERSAL (CWE-22).

Key question: Is user input used to construct a file path?

PATH TRAVERSAL = YES when:
- open()/fopen() path built from user input without sanitization
- User-controlled filename with ../ sequences
- Archive extraction to user-controlled path

SAFE when:
- os.path.basename() applied to user input
- Path normalized with os.path.realpath()
- Whitelist of allowed filenames/directories
- Root directory prefix prevents escape

The code you are reviewing:
```{language}
{code}
```

Return ONLY JSON:
{{"has_vulnerability": bool, "vulnerability_type": "CWE-22 or NONE", "confidence": 0.0-1.0, "severity": "HIGH/MEDIUM/LOW/INFO", "description": "..."}}""",
}


# ===========================================================================
# Strategy 4: Adversarial (argue both sides)
# ===========================================================================

ADVERSARIAL_SYSTEM = """You are a security auditor using an ADVERSARIAL reasoning method.
For each code sample, you must argue BOTH sides before deciding:

1. First, act as a RED TEAM attacker: find every possible way this code could be exploited.
2. Then, act as a BLUE TEAM defender: identify every protection that prevents exploitation.
3. Finally, act as a JUDGE: weigh both arguments and give your final verdict.

You MUST find at least one argument for each side. If you genuinely cannot find
a defense, say so honestly — don't fabricate protections."""

ADVERSARIAL_PROMPT = """Analyze this {language} code using adversarial reasoning.

【Code】
```{language}
{code}
```
{sink_context}

🔴 RED TEAM (Attack): How could this be exploited? What is the attack vector?

🔵 BLUE TEAM (Defense): What protections exist? Length checks? Type safety? Context constraints?

⚖️ JUDGE (Final verdict): Which side has the stronger case?

Return ONLY raw JSON (no markdown, no ```):
{{
  "has_vulnerability": true or false,
  "vulnerability_type": "CWE-XXX or NONE",
  "confidence": 0.0 to 1.0,
  "severity": "HIGH/MEDIUM/LOW/INFO",
  "description": "one sentence",
  "red_team": "attack argument",
  "blue_team": "defense argument"
}}"""


# ===========================================================================
# Strategy 5: Ultra-Strict (flag ONLY when absolutely certain)
# ===========================================================================

STRICT_SYSTEM = """You are an EXTREMELY conservative security auditor.
Your default position: ALL code is SAFE until PROVEN otherwise.

You may ONLY flag a vulnerability when ALL of these are true:
1. You can point to the EXACT line where the bug is.
2. User input DEFINITELY reaches the dangerous function (no guesswork).
3. There is ZERO sanitization — no length check, null guard, type cast, allowlist.
4. The exploit is TRIVIAL — a novice attacker could do it in under 5 minutes.

If you have ANY doubt, ANY uncertainty, or ANY assumption needed → has_vulnerability: false.
A false positive is WORSE than a missed vulnerability. Be RUTHLESS in rejecting uncertain cases.

Confidence MUST be >= 0.95 to report a vulnerability. If you're 94% sure → false."""

STRICT_PROMPT = """Check this {language} code. REMEMBER: default is SAFE. Only flag PROVEN vulnerabilities.

【Code】
```{language}
{code}
```
{sink_context}

Apply the STRICT criteria:
1. Exact line of bug? (must be specific)
2. User input definitely reaches sink? (must be CERTAIN)
3. Zero sanitization? (any check at all → SAFE)
4. Trivially exploitable? (novice-level difficulty)

Return ONLY raw JSON (no markdown, no ```):
{{
  "has_vulnerability": true or false,
  "vulnerability_type": "CWE-XXX or NONE",
  "confidence": 0.0 to 1.0,
  "severity": "HIGH/MEDIUM/LOW/INFO",
  "description": "one sentence — must explain WHY this barely meets the bar, or WHY it was rejected"
}}"""


# ---------------------------------------------------------------------------
# Reviewer class
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Strategy → (system_prompt, user_prompt_template) mapping
# ---------------------------------------------------------------------------

STRATEGY_MAP: dict[str, dict[str, str]] = {
    "baseline": {"system": "BORDERLINE", "prompt": "BORDERLINE"},
    "cot": {"system": "COT", "prompt": "COT"},
    "cwe_specialized": {"system": "CWE", "prompt": "CWE"},
    "adversarial": {"system": "ADVERSARIAL", "prompt": "ADVERSARIAL"},
    "strict": {"system": "STRICT", "prompt": "STRICT"},
}


class SemanticReviewer:
    """Targeted LLM review supporting 5 prompt strategies."""

    def __init__(self, strategy: str = "baseline") -> None:
        from shared.llm.openai_client import create_llm_client
        from src.config import Config
        llm_config = Config()._data.get("llm", Config()._data.get("ollama", {}))
        self.client = create_llm_client(llm_config)
        self.strategy = strategy

    # ------------------------------------------------------------------
    # No-sink review
    # ------------------------------------------------------------------

    def review_no_sink_file(self, code: str, language: str, function_name: str = "") -> dict | None:
        """Review a file with no registered sink matches."""
        prompt = NO_SINK_PROMPT.format(code=code, language=language)
        system = NO_SINK_SYSTEM

        if self.strategy in ("cot", "adversarial", "strict"):
            prompt = NO_SINK_PROMPT.format(code=code, language=language)
            system = NO_SINK_SYSTEM  # keep strict approach for no-sink regardless

        try:
            response = self.client.generate(prompt, system=system, temperature=0.0, max_tokens=2048)
            parsed = LLMOutputParser.parse_and_validate(response)
            if parsed is None:
                return None
            if parsed.get("has_vulnerability"):
                parsed["detection_method"] = f"llm_{self.strategy}"
                parsed["function_name"] = function_name
                return parsed
            return None
        except Exception as e:
            logger.warning(f"No-sink review failed: {e}")
            return None

    # ------------------------------------------------------------------
    # Verify one slice — used for borderline AND full verification
    # ------------------------------------------------------------------

    def verify_slice(self, slice_data: dict) -> dict | None:
        """Verify a slice with the current strategy. Works for any risk level."""
        code = slice_data.get("code", "")
        language = slice_data.get("language", "python")
        sink_category = slice_data.get("sink_category", "unknown")
        sink_type = slice_data.get("sink_type", "unknown")

        # Build sink context line
        sank_detail = slice_data.get("sanitization_detail", "")
        df_path = slice_data.get("dataflow_path", "")
        sink_context = ""
        if sink_type != "unknown":
            parts = [f"Static analysis found: {sink_type} ({sink_category})"]
            if sank_detail:
                parts.append(f"Sanitization: {sank_detail}")
            if df_path:
                parts.append(f"Data flow: {df_path}")
            sink_context = "【Static Analysis Context】\n" + "\n".join(parts) + "\n"

        strategy = self.strategy
        temperature = 0.1

        # --- Strategy dispatch ---
        if strategy == "cot":
            system = COT_SYSTEM
            prompt = COT_PROMPT.format(code=code, language=language, sink_context=sink_context)
            temperature = 0.2
        elif strategy == "cwe_specialized":
            cwe_prompt = CWE_PROMPTS.get(sink_category)
            if cwe_prompt:
                system = "You are a security auditor specialized in this vulnerability type."
                prompt = cwe_prompt.format(code=code, language=language)
            else:
                system = BORDERLINE_SYSTEM
                prompt = BORDERLINE_PROMPT.format(
                    code=code, language=language, sink_type=sink_type,
                    sink_category=sink_category, risk_level=slice_data.get("risk_level", "?"),
                    sanitization_detail=sank_detail, dataflow_path=df_path,
                )
            temperature = 0.1
        elif strategy == "adversarial":
            system = ADVERSARIAL_SYSTEM
            prompt = ADVERSARIAL_PROMPT.format(code=code, language=language, sink_context=sink_context)
            temperature = 0.3
        elif strategy == "strict":
            system = STRICT_SYSTEM
            prompt = STRICT_PROMPT.format(code=code, language=language, sink_context=sink_context)
            temperature = 0.0
        else:  # baseline
            system = BORDERLINE_SYSTEM
            prompt = BORDERLINE_PROMPT.format(
                code=code, language=language, sink_type=sink_type,
                sink_category=sink_category, risk_level=slice_data.get("risk_level", "?"),
                sanitization_detail=sank_detail, dataflow_path=df_path,
            )
            temperature = 0.3

        try:
            response = self.client.generate(prompt, system=system, temperature=temperature, max_tokens=2048)
            parsed = LLMOutputParser.parse_and_validate(response)
            if parsed is None:
                return None

            result = dict(slice_data)
            result["llm_verified"] = True
            result["llm_strategy"] = strategy
            result["llm_has_vulnerability"] = parsed.get("has_vulnerability", True)
            result["llm_confidence"] = parsed.get("confidence", 0.5)
            result["llm_reasoning"] = parsed.get("reasoning", parsed.get("description", ""))

            if not parsed.get("has_vulnerability"):
                result["risk_level"] = "low"
                result["has_vulnerability"] = False
                result["status"] = f"SAFE (LLM-{strategy})"
            else:
                result["has_vulnerability"] = True
                result["status"] = f"VULN (LLM-{strategy})"

            logger.info(
                f"  [LLM-{strategy}] {slice_data.get('function_name', '?')}: "
                f"vuln={parsed.get('has_vulnerability')} conf={parsed.get('confidence', 0):.2f}"
            )
            return result
        except Exception as e:
            logger.warning(f"LLM verification ({strategy}) failed: {e}")
            return None

    # ------------------------------------------------------------------
    # Backward-compatible wrappers
    # ------------------------------------------------------------------

    def verify_borderline(self, slice_data: dict) -> dict | None:
        """Verify a borderline slice (medium risk). Alias for verify_slice."""
        return self.verify_slice(slice_data)

    def verify_all(self, slice_data: dict) -> dict | None:
        """Verify ANY slice including high-risk ones. Alias for verify_slice."""
        return self.verify_slice(slice_data)

    # ------------------------------------------------------------------
    # Full-file sweep
    # ------------------------------------------------------------------

    def full_file_sweep(self, code: str, language: str, file_path: str = "") -> list[dict]:
        """Full-file LLM review catching anything static analysis missed."""
        prompt = FULL_FILE_PROMPT.format(code=code, language=language)
        try:
            response = self.client.generate(prompt, system=FULL_FILE_SYSTEM, temperature=0.3, max_tokens=2048)
            parsed = LLMOutputParser.parse(response)
            if parsed is None:
                return []
            findings = parsed.get("findings", [])
            for f in findings:
                f["file"] = file_path
                f["detection_method"] = "llm_full_sweep"
                f["language"] = language
            if findings:
                logger.info(f"  [LLM Sweep] {file_path}: {len(findings)} finding(s)")
            return findings
        except Exception as e:
            logger.warning(f"Full-file sweep failed: {e}")
            return []


# ===========================================================================
# Multi-Agent Reviewer — 3 agents from different angles, ≥2 votes to flag
# ===========================================================================

# Specialized no-sink prompts for each agent role
AGENT_STRICT_NO_SINK = """You are an EXTREMELY conservative code security auditor.
Your default: ALL code is SAFE until PROVEN otherwise with concrete, specific evidence.

You may ONLY flag a vulnerability when ALL of these are true:
1. You can point to the EXACT line with the bug.
2. There is a clear, exploitable security impact (not just "bad practice").
3. The exploit path is concrete — an attacker could realistically trigger it.
4. There is NO effective protection (null check, bounds guard, sanitization).

If you have ANY doubt → has_vulnerability: false. Be RUTHLESS in rejecting uncertain cases.
Confidence must be >= 0.90 to report."""

AGENT_ADVERSARIAL_NO_SINK = """You are a security auditor using ADVERSARIAL reasoning.
For each code sample, argue BOTH sides before deciding:

1. RED TEAM: Find every possible exploit path — be creative, be thorough.
2. BLUE TEAM: Identify every protection, constraint, and mitigating factor.
3. JUDGE: Weigh both sides. Which is stronger? Give a clear verdict.

Be honest — if the defense is strong, say SAFE. If the attack is stronger, flag it."""

AGENT_COT_NO_SINK = """You are a senior security auditor. Think STEP BY STEP:

STEP 1 — Identify ALL dangerous operations (function calls, memory access, pointer use).
STEP 2 — For each, trace: does untrusted data reach this operation?
STEP 3 — Check protections: is there validation/sanitization BEFORE the dangerous op?
STEP 4 — Assess real-world exploitability: can an attacker trigger this? What's the impact?
STEP 5 — Final verdict with confidence.

Only flag if ALL steps confirm a real, exploitable vulnerability."""

NO_SINK_MULTI_PROMPT = """Analyze this {language} code for security vulnerabilities.

【Code】
```{language}
{code}
```

Return ONLY raw JSON (no markdown, no ```):
{{"has_vulnerability": bool, "vulnerability_type": "CWE-XXX or NONE", "confidence": 0.0-1.0, "severity": "HIGH/MEDIUM/LOW/INFO", "description": "brief — must reference specific code"}}"""


class MultiAgentReviewer:
    """3-agent parallel review with majority voting for no-sink code.

    Agents: STRICT (conservative) + ADVERSARIAL (balanced) + COT (step-by-step)
    Voting: ≥2 must agree on has_vulnerability=True to flag.
    This design prioritizes PRECISION over recall — FP reduction is the goal.
    """

    def __init__(self) -> None:
        from shared.llm.openai_client import create_llm_client
        from src.config import Config
        Config.reset()
        llm_config = Config()._data.get("llm", Config()._data.get("ollama", {}))
        self.client = create_llm_client(llm_config)
        self.total_calls = 0

    def review_no_sink(self, code: str, language: str, function_name: str = "") -> dict | None:
        """Run 3 agents on no-sink code, return majority verdict.

        Returns None if <2 agents flag it as vulnerable.
        """
        prompt = NO_SINK_MULTI_PROMPT.format(code=code, language=language)
        agents = [
            ("strict", AGENT_STRICT_NO_SINK, 0.0),
            ("adversarial", AGENT_ADVERSARIAL_NO_SINK, 0.2),
            ("cot", AGENT_COT_NO_SINK, 0.1),
        ]

        votes = []
        findings = []
        for agent_name, system, temp in agents:
            try:
                response = self.client.generate(prompt, system=system, temperature=temp, max_tokens=1536)
                self.total_calls += 1
                parsed = LLMOutputParser.parse_and_validate(response)
                if parsed and parsed.get("has_vulnerability"):
                    confidence = parsed.get("confidence", 0)
                    findings.append((agent_name, parsed))
                    if confidence >= 0.75:
                        votes.append(True)
                    else:
                        votes.append(False)
                else:
                    votes.append(False)
            except Exception as e:
                logger.warning(f"Agent {agent_name} failed: {e}")
                votes.append(False)

        vuln_count = sum(votes)
        agent_names = [a[0] for a in agents]
        logger.info(
            f"  [MultiAgent] {function_name}: {vuln_count}/3 votes "
            f"({'FLAG' if vuln_count>=2 else 'SAFE'}) "
            f"votes={list(zip(agent_names, votes))}"
        )

        if vuln_count >= 2:
            best = max(findings, key=lambda x: x[1].get("confidence", 0))
            result = best[1]
            result["detection_method"] = f"multi_agent_{vuln_count}v"
            result["function_name"] = function_name
            result["agent_votes"] = vuln_count
            result["agent_details"] = [{"agent": n, "confidence": f.get("confidence", 0)}
                                       for n, f in findings]
            return result

        return None

    def review_no_sink_batch(self, files: list[tuple[str, str, str]]) -> list[dict]:
        """Review multiple no-sink files. Returns confirmed findings only.

        Args:
            files: list of (code, language, function_name) tuples
        """
        findings = []
        for i, (code, lang, fn) in enumerate(files):
            f = self.review_no_sink(code, lang, fn)
            if f:
                findings.append(f)
            if (i + 1) % 10 == 0:
                logger.info(f"  [MultiAgent batch] {i+1}/{len(files)} reviewed, "
                            f"{len(findings)} vulns found ({self.total_calls} calls)")
        return findings
