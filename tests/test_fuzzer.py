"""
Unit Tests for Schema Fuzzer & Boundary Stresser
"""

import pytest
from scanner.fuzzer import SchemaFuzzer


def test_schema_fuzzer_generates_mutation_matrix():
    tool_def = {
        "name": "query_database",
        "description": "Executes search query on customer database",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search term"},
                "limit": {"type": "integer", "description": "Max results"}
            },
            "required": ["query"]
        }
    }

    mutations = SchemaFuzzer.fuzz_tool(tool_def)

    assert len(mutations) > 10
    fuzz_types = [m["fuzz_type"] for m in mutations]

    # Verify boundary and type confusion vectors
    assert "empty_arguments" in fuzz_types
    assert "shadow_argument_pollution" in fuzz_types
    assert any("type_confusion_query" in ft for ft in fuzz_types)
    assert any("numeric_boundary_limit" in ft for ft in fuzz_types)
    assert any("injection_query" in ft for ft in fuzz_types)

    # Check shadow argument structure
    shadow_case = next(m for m in mutations if m["fuzz_type"] == "shadow_argument_pollution")
    assert "__proto__" in shadow_case["arguments"]
