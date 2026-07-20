"""Tests for LLM output parser."""

import pytest

from src.llm.parser import LLMOutputParser


class TestLLMParser:
    def test_parse_json_block(self):
        response = '''```json
{"has_vulnerability": true, "vulnerability_type": "CWE-78", "confidence": 0.9}
```'''
        result = LLMOutputParser.parse(response)
        assert result is not None
        assert result["has_vulnerability"] is True
        assert result["confidence"] == 0.9

    def test_parse_raw_json(self):
        response = '{"has_vulnerability": false, "confidence": 0.1}'
        result = LLMOutputParser.parse(response)
        assert result is not None
        assert result["has_vulnerability"] is False

    def test_parse_stage1_response(self):
        response = '{"suspicious": true, "reason": "uses eval with user input"}'
        result = LLMOutputParser.parse(response)
        assert result is not None
        assert result["suspicious"] is True

    def test_parse_invalid(self):
        result = LLMOutputParser.parse("just some text, no json here")
        assert result is None

    def test_validate_clamps_confidence(self):
        validated = LLMOutputParser.validate(
            {"has_vulnerability": True, "confidence": 2.5}
        )
        assert validated["confidence"] == 1.0

    def test_validate_defaults(self):
        validated = LLMOutputParser.validate({})
        assert validated["has_vulnerability"] is False
        assert validated["confidence"] == 0.0
        assert validated["vulnerability_type"] == "UNKNOWN"
        assert validated["line_numbers"] == []
