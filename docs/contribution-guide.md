# Contribution Guide: MCP Sentinel Mesh

## 1. Development Standards
- Maintain 100% deterministic decision-making in core security rules.
- Add unit tests for every new scanner rule under `tests/test_scanner.py`.
- Ensure all 80 adversarial test cases pass before submitting pull requests.

---

## 2. Adding a New Scanner Rule
1. Create a class subclassing `BaseRule` in `scanner/rules/rules_impl.py`.
2. Define a unique rule code (`SEC-MCP-016`, etc.), severity, title, and remediation advice.
3. Register the rule in `ALL_RULES` within `scanner/rules/rules_impl.py`.
4. Document the rule in `docs/rules-catalog.md`.
5. Add positive and negative test cases in `tests/test_scanner.py`.

---

## 3. Submitting Pull Requests
- Format code cleanly.
- Run `python -m pytest tests/` to verify test suite passes.
- Run `npm --prefix frontend run build` to verify frontend compiles.
