"""Centralized registry of sink functions, source patterns, and sanitization rules.

All security-relevant patterns are defined here so they can be reviewed,
extended, and versioned independently of the analysis engine.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Source definitions — where attacker-controlled data enters the program
# ---------------------------------------------------------------------------

SOURCES: dict[str, dict[str, list[str]]] = {
    "c": {
        "function_calls": [
            "gets", "scanf", "read", "recv", "recvfrom",
            "fgets", "getenv", "getcwd", "getwd",
            "readlink", "realpath",
        ],
        "variables": [
            "argv", "argc", "environ",
        ],
        "patterns": [
            "stdin", "cin", "getchar",
        ],
    },
    "python": {
        "function_calls": [
            "input", "getattr", "__import__",
            "eval", "exec",  # both source and sink depending on context
        ],
        "credential_patterns": [
            "password", "passwd", "secret", "api_key", "api_secret",
            "token", "private_key", "access_key",
        ],
        "objects": [
            "request.args", "request.form", "request.json",
            "request.cookies", "request.headers", "request.files",
            "request.data", "request.values",
            "os.environ", "sys.argv",
        ],
        "patterns": [
            ".read()", ".readlines()", "socket.recv",
            "urlopen(", "requests.get(", "requests.post(",
        ],
    },
    "java": {
        "function_calls": [],
        "objects": [
            "request.getParameter", "request.getQueryString",
            "request.getHeader", "request.getCookies",
            "request.getInputStream", "request.getReader",
            "request.getParameterValues", "request.getParameterMap",
            "System.getenv", "System.getProperty",
        ],
        "patterns": [
            "@RequestParam", "@PathVariable", "@RequestBody",
            "@RequestHeader", "@CookieValue",
        ],
    },
}

# ---------------------------------------------------------------------------
# Sink definitions — dangerous operations categorized by vulnerability type
# ---------------------------------------------------------------------------

SINKS: dict[str, dict[str, list[str]]] = {
    "c": {
        "buffer_overflow": [
            "strcpy", "strcat", "sprintf", "memcpy", "gets",
            "scanf", "wcscpy", "wcscat", "swprintf",
            "_mbscpy", "_mbscat", "lstrcpy", "lstrcat",
            "bcopy", "memmove",  # overlapping / unbounded mem ops
            "strdup", "strndup",  # alloc based on input string length
        ],
        "command_injection": [
            "system", "popen", "execve", "execl", "execvp",
            "execle", "execlp", "execvpe", "CreateProcess",
            "_exec", "_spawn", "_system", "_popen",
            "ShellExecute", "ShellExecuteEx",
        ],
        "format_string": [
            "printf", "sprintf", "syslog",
            "vsprintf", "vprintf", "fprintf",
            "snprintf",  # format string vuln still possible with %n
            "dprintf", "vdprintf",
        ],
        "memory_corruption": [
            "memmove",  # overlapping mem move
            "free",     # double-free / use-after-free (medium risk, needs dataflow)
            "realloc",  # UAF if not checked, size overflow
            "alloca",   # stack alloc with variable size → overflow
            "memset",   # zeroing wrong size
            "memcmp",   # comparing wrong size → info leak
            "_malloca", "_freea",
        ],
        "path_traversal": [
            "fopen", "open", "stat", "access",
            "chmod", "chown", "realpath",
            "opendir", "readlink", "unlink",
            "rename", "remove", "mkdir", "rmdir",
            "creat", "openat", "fopen_s",
        ],
        "integer_overflow": [
            "malloc",   # check for overflow in size calculation before malloc
            "calloc",   # num*size overflow
            "realloc",  # new_size overflow
            "alloca",   # stack alloc with variable size
        ],
        "race_condition": [
            "access",   # TOCTOU: access() then open()
            "stat",     # stat() then open() race
            "fopen",    # combined with stat
            "open",     # combined with access
        ],
    },
    "python": {
        "command_injection": [
            "os.system", "os.popen", "subprocess.call",
            "subprocess.Popen", "subprocess.run",
            "subprocess.check_output", "subprocess.check_call",
            "os.execv", "os.execve", "os.execl", "os.execle",
            "os.spawnl", "os.spawnv", "os.spawnlp",
            "asyncio.create_subprocess_shell",
        ],
        "code_injection": [
            "eval", "exec", "compile", "__import__",
            "importlib.import_module",
        ],
        "deserialization": [
            "pickle.loads", "pickle.load", "pickle.Unpickler",
            "yaml.load", "yaml.unsafe_load",
            "marshal.loads", "dill.loads",
            "jsonpickle.decode", "torch.load",
        ],
        "sql_injection": [
            "cursor.execute", "connection.execute",
            ".raw(", "RawSQL(",
        ],
        "path_traversal": [
            "os.remove", "os.rename", "os.mkdir",
            "shutil.copy", "shutil.move", "shutil.rmtree",
            "tarfile.extractall", "zipfile.extractall",
            "open(",       # path traversal when path built from user input
        ],
        "ssrf": [
            "requests.get", "requests.post", "requests.put",
            "requests.delete", "requests.patch", "requests.head",
            "urllib.request.urlopen", "urllib.request.urlretrieve",
            "httpx.get", "httpx.post", "httpx.request",
            "aiohttp.ClientSession",
        ],
        "xss": [
            "render_template_string", "Markup(",
            "html.concat", "Response(",
        ],
        "credential_hardcoding": [
            "mysql_connect", "pymysql.connect", "psycopg2.connect",
            "sqlite3.connect", "pyodbc.connect", "cx_Oracle.connect",
            "connect(", "authenticate(", "login(",
        ],
    },
    "java": {
        "sql_injection": [
            "Statement.executeQuery", "Statement.execute",
            "Statement.executeUpdate", "Statement.addBatch",
            "createStatement", "prepareStatement(",
        ],
        "command_injection": [
            "Runtime.exec", "Runtime.getRuntime().exec",
            "ProcessBuilder(", "ProcessBuilder.start",
        ],
        "xss": [
            "response.getWriter().write", "response.getWriter().print",
            "response.getWriter().println",
            "out.println(", "out.print(",
        ],
        "deserialization": [
            "ObjectInputStream.readObject", "readObject(",
            "XMLDecoder.readObject", "XStream.fromXML",
            "ObjectInputStream(", "readUnshared",
        ],
        "path_traversal": [
            "FileInputStream(", "FileOutputStream(", "FileReader(",
            "FileWriter(", "File(", "Paths.get(",
            "new FileInputStream", "new FileReader",
        ],
        "xxe": [
            "DocumentBuilder.parse", "SAXParser.parse",
            "XMLReader.parse", "SAXReader.read",
            "DocumentBuilderFactory.newInstance",
            "SAXParserFactory.newInstance",
            "XMLInputFactory.createXMLStreamReader",
        ],
        "ssrf": [
            "URL.openConnection", "URL.openStream",
            "HttpURLConnection", "HttpClient.execute",
            "RestTemplate.getForObject", "RestTemplate.postForObject",
            "WebClient.create",
        ],
    },
}

# ---------------------------------------------------------------------------
# Sanitization patterns — regex for input validation / escaping
# ---------------------------------------------------------------------------

SANITIZATION_PATTERNS: dict[str, list[tuple[str, str]]] = {
    "c": [
        # length_check: strlen(x) >= sizeof/MAX/LIMIT
        (r"if\s*\(.*(?:str)?len\s*\([^)]*\).*?[<>=!]+\s*(?:sizeof|MAX|SIZE|BUFSIZ|LIMIT|BUFFER|LEN)(?![a-zA-Z])",
         "length_check"),
        # size_guard: var/expr OP (number|sizeof|MAX...) — non-greedy
        (r"if\s*\([^)]*?[<>=!]+\s*(?:\d+|sizeof|MAX|SIZE|BUFSIZ|LIMIT|BUFFER|LEN)(?![a-zA-Z])",
         "size_guard"),
        # numeric_bound: len/size/count/n OP number)
        (r"if\s*\([^)]*?\b(?:len|size|count|length|n)\b\s*[<>=!]+\s*\d+\s*\)",
         "numeric_bound"),
        # sizeof_bound: anything involving sizeof in an if-condition
        (r"if\s*\(.*\bsizeof\s*\(?[^)]*\)?\s*[<>=!]", "sizeof_bound"),
        (r"snprintf\s*\(", "safe_snprintf"),
        (r"strncpy\s*\(", "safe_strncpy"),
        (r"strncat\s*\(", "safe_strncat"),
        (r"fgets\s*\([^,]+,\s*(?:MAX|SIZE|sizeof|BUFSIZ|LIMIT)", "safe_fgets"),
        (r"if\s*\([^)]*\bNULL\b[^)]*\)", "null_check"),
        (r"if\s*\([^)]*\bptr\s*!=\s*NULL", "null_check_ptr"),
        (r"scanf\s*\(\s*\"\%\d+s", "scanf_bounded"),
        # printf with format string literal (safe — e.g. printf(\"%%s\", var))
        (r"printf\s*\(\s*\"", "printf_format_literal"),
        # double-free guard — handles ptr->field = NULL, ptr = NULL, *ptr = NULL
        (r"if\s*\([^)]*\bNULL\b[^)]*\)\s*\{[^}]*free\s*\(|free\s*\([^)]*\)\s*;\s*\S+\s*=\s*NULL",
         "safe_free"),
        # strchr null-result guard (e.g. strchr(x, '.') != NULL)
        (r"strchr\s*\([^)]*\)\s*!=\s*NULL",
         "strchr_null_check"),
        # memcpy with sizeof destination
        (r"memcpy\s*\([^,]+,\s*[^,]+,\s*sizeof\s*\(",
         "memcpy_sizeof"),
        # strncat with sizeof (bounded concat)
        (r"strncat\s*\([^,]+,\s*[^,]+,\s*sizeof",
         "strncat_bounded"),
        # snprintf with sizeof (bounded format)
        (r"snprintf\s*\([^,]+,\s*sizeof",
         "snprintf_bounded"),
        # token NULL guard after strtok
        (r"strtok\s*\([^)]*\).*?\bNULL\b",
         "token_null_guard"),
        # general ptr null guard — deref-safe check
        (r"if\s*\(\s*!\s*\w+\s*\)\s*return\s+(?:NULL|0|false)",
         "ptr_null_guard_early_return"),
        # sizeof comparison in either direction: sizeof(x) < n OR n >= sizeof(x)
        (r"if\s*\(.*[<>=!]+\s*sizeof\s*\(?[^)]*\)?",
         "sizeof_bound_reverse"),
    ],
    "python": [
    ],
    "python": [
        # String sanitization
        (r"\.strip\(\)|\.lstrip\(\)|\.rstrip\(\)", "strip"),
        (r"re\.(?:sub|escape|match|search|fullmatch)\(", "regex_sanitize"),
        (r"html\.escape\(|markupsafe\.escape\(|cgi\.escape\(", "html_escape"),
        # Type casting
        (r"\bint\s*\(|\bfloat\s*\(|\bstr\s*\(|\bbool\s*\(|\blist\s*\(|\bdict\s*\(", "type_cast"),
        # Shell escaping
        (r"shlex\.quote\(|pipes\.quote\(|escape\(.*\)", "shell_escape"),
        # SQL — parameterized queries
        (r"cursor\.execute\([^,]+,\s*\(|execute\([^,]+,\s*\[", "parameterized_query"),
        # File path
        (r"os\.path\.(?:basename|abspath|realpath|normpath|dirname)\(", "path_normalize"),
        # Deserialization — safe alternatives
        (r"yaml\.safe_load\(|json\.loads\(|ast\.literal_eval\(|ast\.parse\(|ast\.walk\(", "safe_parse"),
        # Safe eval pattern (AST whitelist + restricted builtins)
        (r"ast\.walk\(.*\).*allowed|allowed.*ast\.walk", "safe_eval_ast_whitelist"),
        # Subprocess — safe usage (list args, not shell string)
        (r"subprocess\.(?:call|Popen|run)\(\[", "subprocess_list_args"),
        # Exec sandbox — restricted builtins
        (r"__builtins__\s*=|safe_builtins|safe_globals", "exec_sandbox"),
        # Input allowlist — inline literal OR variable reference
        (r"if\s+\w+\s+(?:not\s+)?in\s+(?:[\[({]|\w+)", "allowlist_check"),
        # Command allowlist — list [...] or set {...} of strings
        (r"[\[{]\s*\"[^\"]+\"(?:\s*,\s*(?:\"[^\"]+\"|\w+))*\s*[\]}]", "command_allowlist"),
        # Safe file read — only safe loaders, NOT open() (too broad, FPs on vuln files)
        (r"json\.load\(|yaml\.safe_load\(|csv\.reader\(", "safe_read"),
        # Env-var credential (safe pattern for credential_hardcoding)
        (r"os\.(?:environ|getenv)\.get\(|os\.environ\[|getenv\(", "env_var_credential"),
    ],
    "java": [
        (r"PreparedStatement", "prepared_statement"),
        (r"\.escapeHtml\(|\.escapeXml\(|StringEscapeUtils\.", "output_encoding"),
        (r"Pattern\.matches\(|\.matches\(.*regex", "input_validation"),
        (r"File\.createTempFile\(|Paths\.get\([^)]*\)\.normalize\(\)", "path_safe"),
        (r"!= null\s*&&|null\s*==", "null_check"),
        (r"try\s*\{|catch\s*\(.*Exception", "exception_handling"),
    ],
}

# ---------------------------------------------------------------------------
# Risk level assignment for sink categories
# ---------------------------------------------------------------------------

SINK_RISK_LEVELS: dict[str, str] = {
    "code_injection": "high",
    "command_injection": "high",
    "deserialization": "high",
    "sql_injection": "high",
    "xxe": "high",
    "buffer_overflow": "high",
    "format_string": "medium",
    "ssrf": "medium",
    "xss": "medium",
    "path_traversal": "medium",
    "memory_corruption": "medium",
    "integer_overflow": "medium",
    "race_condition": "medium",
    "credential_hardcoding": "high",
}


def get_risk_level(sink_category: str) -> str:
    """Return the risk level for a given sink category."""
    return SINK_RISK_LEVELS.get(sink_category, "medium")
