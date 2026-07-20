"""Tests for the upgraded code slicer with dataflow and sanitization."""

from pathlib import Path

import pytest

from src.scanner.code_slicer import CodeSlicer


class TestCodeSlicer:
    """Test the upgraded code slicer."""

    def setup_method(self):
        self.slicer = CodeSlicer()

    # C tests -----------------------------------------------------------

    def test_c_buffer_overflow_detected(self):
        code = """
#include <string.h>
void vuln(char* input) {
    char buf[64];
    strcpy(buf, input);
}
"""
        slices = self.slicer.slice_code(code, "c")
        assert len(slices) >= 1
        slc = slices[0]
        assert slc["sink_type"] == "strcpy"
        assert slc["sink_category"] == "buffer_overflow"
        assert slc["function_name"] == "vuln"

    def test_c_safe_with_length_check(self):
        code = """
#include <string.h>
void safe(char* input) {
    char buf[64];
    if (strlen(input) < sizeof(buf)) {
        strcpy(buf, input);
    }
}
"""
        slices = self.slicer.slice_code(code, "c")
        if slices:
            # Should have sanitization detected
            assert slices[0].get("has_sanitization") or slices[0].get(
                "risk_level"
            ) in ("medium", "low")

    def test_c_command_injection(self):
        code = """
#include <stdlib.h>
void vuln(char* cmd) {
    system(cmd);
}
"""
        slices = self.slicer.slice_code(code, "c")
        assert len(slices) >= 1
        assert slices[0]["sink_type"] == "system"
        assert slices[0]["sink_category"] == "command_injection"

    # Python tests ------------------------------------------------------

    def test_python_eval_detected(self):
        code = """
def vuln(user_input):
    result = eval(user_input)
    return result
"""
        slices = self.slicer.slice_code(code, "python")
        assert len(slices) >= 1
        assert slices[0]["sink_type"] == "eval"
        assert slices[0]["sink_category"] == "code_injection"

    def test_python_safe_json(self):
        code = """
import json
def safe(user_input):
    data = json.loads(user_input)
    return data
"""
        slices = self.slicer.slice_code(code, "python")
        # json.loads is not in sink list — should be empty or safe
        safe_slices = [s for s in slices if s["sink_type"] == "json.loads"]
        assert len(safe_slices) == 0

    def test_python_sql_injection(self):
        code = '''
def vuln(user_id):
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
'''
        slices = self.slicer.slice_code(code, "python")
        assert len(slices) >= 1
        assert "execute" in slices[0]["sink_type"]

    def test_python_pickle_deserialization(self):
        code = """
import pickle
def vuln(data):
    obj = pickle.loads(data)
    return obj
"""
        slices = self.slicer.slice_code(code, "python")
        assert len(slices) >= 1
        assert "pickle.loads" in slices[0]["sink_type"]

    # Metadata tests ----------------------------------------------------

    def test_slice_has_line_numbers(self):
        code = """
def test():
    eval("1+1")
"""
        slices = self.slicer.slice_code(code, "python")
        assert slices[0]["line_start"] > 0
        assert slices[0]["line_end"] >= slices[0]["line_start"]

    def test_slice_has_risk_level(self):
        code = """
#include <stdlib.h>
void vuln(char* cmd) { system(cmd); }
"""
        slices = self.slicer.slice_code(code, "c")
        assert slices[0]["risk_level"] in ("high", "medium", "low")
        assert slices[0]["ast_confidence"] > 0

    def test_python_safe_with_parameterized_query(self):
        code = '''
def safe(user_id):
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
'''
        slices = self.slicer.slice_code(code, "python")
        if slices:
            assert slices[0].get("has_sanitization") or slices[0].get(
                "risk_level"
            ) != "high"
