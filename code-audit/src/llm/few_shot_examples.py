"""Static few-shot example library for C and Python vulnerabilities.

These are hand-curated canonical examples used when RAG retrieval is
unavailable (baseline mode) or as a supplement.
"""

from __future__ import annotations

FEW_SHOT_EXAMPLES: dict[str, str] = {
    "c": """
Example 1 [CWE-121 — Buffer Overflow]:
```c
void vulnerable(char* user_input) {
    char buf[64];
    strcpy(buf, user_input);  // VULNERABLE: no bounds check
}
```
{"has_vulnerability": true, "vulnerability_type": "CWE-121", "confidence": 0.95, "severity": "HIGH", "remediation": "Use strncpy(buf, user_input, sizeof(buf)-1); buf[sizeof(buf)-1] = '\\0';"}

Example 2 [Safe — proper bounds check]:
```c
void safe(char* user_input) {
    char buf[64];
    if (strlen(user_input) < sizeof(buf)) {
        strcpy(buf, user_input);  // SAFE: bounds checked
    }
}
```
{"has_vulnerability": false, "confidence": 0.9, "severity": "INFO"}
""",

    "python": """
Example 1 [CWE-78 — Command Injection]:
```python
def vulnerable(user_input):
    os.system(f"ls {user_input}")  # VULNERABLE: shell injection
```
{"has_vulnerability": true, "vulnerability_type": "CWE-78", "confidence": 0.95, "severity": "HIGH", "remediation": "Use subprocess.run(['ls', user_input], shell=False)"}

Example 2 [CWE-89 — SQL Injection]:
```python
def vulnerable(user_id):
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")  # VULNERABLE
```
{"has_vulnerability": true, "vulnerability_type": "CWE-89", "confidence": 0.95, "severity": "HIGH", "remediation": "Use parameterized query: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))"}

Example 3 [Safe — Parameterized Query]:
```python
def safe(user_id):
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))  # SAFE
```
{"has_vulnerability": false, "confidence": 0.9, "severity": "INFO"}
""",

    "java": """Example 1 [CWE-89 — SQL Injection]:
```java
public void vulnerable(String userId) {
    Statement stmt = conn.createStatement();
    stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);  // VULNERABLE
}
```
{"has_vulnerability": true, "vulnerability_type": "CWE-89", "confidence": 0.95, "severity": "HIGH", "remediation": "Use PreparedStatement"}
""",
}
