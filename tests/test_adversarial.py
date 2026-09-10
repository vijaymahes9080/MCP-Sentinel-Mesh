"""
Unit and Integration Tests for Adversarial Test Engine
"""

import pytest
from scanner.adversarial.engine import AdversarialTestEngine
from scanner.adversarial.corpus import CORPUS
from proxy.policy import PolicyEngine


def test_corpus_count():
    # Enforces requirement of at least 80 cases
    assert len(CORPUS) >= 80


def test_adversarial_engine_execution():
    engine = AdversarialTestEngine()
    policy = PolicyEngine()
    results = engine.run_all(policy_evaluator=policy)
    assert len(results) == len(CORPUS)
    passed = sum(1 for r in results if r.passed)
    pass_rate = (passed / len(results)) * 100
    assert pass_rate >= 90.0, f"Expected pass rate >= 90%, got {pass_rate}%"
