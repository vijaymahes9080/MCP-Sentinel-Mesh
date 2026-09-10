# Autonomous Schema Fuzzing & Adversarial Testing

## Overview

MCP Sentinel Mesh provides a dual-layer adversarial security testing engine:
1. **Adversarial Test Suite** (`scanner/adversarial/`): 80 standardized test vectors across 8 attack categories (Prompt Injection, Excessive Permissions, SSRF, Data Exfiltration, Replay Attacks, etc.).
2. **Autonomous Schema Fuzzer** (`scanner/fuzzer.py`): Automatically discovers edge-case parameter boundaries, prototype pollution vectors, and type confusion payloads directly from tool input schemas.

---

## Running the Adversarial Suite

To run the complete benchmark evaluation suite and generate evaluation metrics:

```bash
python tests/evaluation/run_benchmarks.py
```

This outputs:
- `evaluation.json`: Comprehensive structured benchmark telemetry.
- `evaluation.md`: GitHub-flavored Markdown evaluation report.
- `docs/benchmark_charts.png`: Visual multi-panel benchmark distribution graph.
- `docs/index.html`: Interactive standalone Chart.js dashboard.

---

## Running the Schema Fuzzer

To fuzz an MCP tool definition before deployment:

```python
from scanner.fuzzer import SchemaFuzzer

my_tool = {
    "name": "search_customer_records",
    "description": "Searches internal CRM records",
    "inputSchema": {
        "type": "object",
        "properties": {
            "query": {"type": "string"},
            "limit": {"type": "integer"}
        },
        "required": ["query"]
    }
}

mutations = SchemaFuzzer.fuzz_tool(my_tool)
print(f"Generated {len(mutations)} boundary attack test cases.")

for case in mutations[:3]:
    print(f"Type: {case['fuzz_type']} -> Args: {case['arguments']}")
```
