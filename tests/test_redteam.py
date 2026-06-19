# MIT License — Copyright (c) 2026 Diviqra
import pytest

from redteam.attacks import direct_injection, hindi_attacks, jailbreak, pii_extraction, system_prompt_leak
from redteam.scorer import RunMetrics, compute
from redteam.reporter import generate


class TestAttackCorpora:
    def test_direct_injection_has_attacks(self):
        attacks = direct_injection.load()
        assert len(attacks) >= 10

    def test_jailbreak_has_attacks(self):
        attacks = jailbreak.load()
        assert len(attacks) >= 10

    def test_pii_extraction_has_attacks(self):
        attacks = pii_extraction.load()
        assert len(attacks) >= 10

    def test_system_prompt_leak_has_attacks(self):
        attacks = system_prompt_leak.load()
        assert len(attacks) >= 10

    def test_hindi_attacks_has_attacks(self):
        attacks = hindi_attacks.load()
        assert len(attacks) >= 10

    def test_load_with_limit(self):
        attacks = direct_injection.load(limit=5)
        assert len(attacks) == 5

    def test_all_attacks_have_prompts(self):
        for module in [direct_injection, jailbreak, pii_extraction, system_prompt_leak, hindi_attacks]:
            for attack in module.load():
                assert attack.prompt
                assert len(attack.prompt) > 5

    def test_all_attacks_have_owasp_category(self):
        for module in [direct_injection, jailbreak, pii_extraction, system_prompt_leak, hindi_attacks]:
            for attack in module.load():
                assert attack.owasp_category.startswith("LLM")


class TestScorer:
    def _make_results(self, total: int, detected: int) -> list[dict]:
        results = []
        for i in range(total):
            results.append({
                "detected": i < detected,
                "final_action": "block" if i < detected else "allow",
                "wall_triggered": "wall1" if i < detected // 2 else "wall2",
                "latency_ms": 10,
                "owasp_category": "LLM01",
                "attack_type": "direct_injection",
            })
        return results

    def test_detection_rate_computed(self):
        results = self._make_results(total=100, detected=95)
        metrics = compute("test-run", results)
        assert metrics.detection_rate == 0.95
        assert metrics.total == 100
        assert metrics.detected == 95

    def test_zero_detection_rate_zero(self):
        results = self._make_results(total=10, detected=0)
        metrics = compute("test-run", results)
        assert metrics.detection_rate == 0.0

    def test_avg_latency_computed(self):
        results = self._make_results(total=10, detected=10)
        metrics = compute("test-run", results)
        assert metrics.avg_latency_ms == 10.0

    def test_by_owasp_populated(self):
        results = self._make_results(total=10, detected=8)
        metrics = compute("test-run", results)
        assert "LLM01" in metrics.by_owasp
        assert metrics.by_owasp["LLM01"]["total"] == 10


class TestReporter:
    def test_report_has_summary(self):
        results = [{"detected": True, "final_action": "block", "wall_triggered": "wall1", "latency_ms": 5, "owasp_category": "LLM01", "attack_type": "direct"}]
        metrics = compute("run-1", results)
        report = generate("run-1", metrics, results)
        assert "summary" in report
        assert report["summary"]["total_attacks"] == 1
        assert report["summary"]["detected"] == 1
        assert report["run_id"] == "run-1"

    def test_report_status_pass_when_above_threshold(self):
        results = [{"detected": True, "final_action": "block", "wall_triggered": "wall1", "latency_ms": 5, "owasp_category": "LLM01", "attack_type": "direct"}]
        metrics = compute("run-1", results)
        report = generate("run-1", metrics, results)
        assert report["summary"]["status"] == "PASS"

    def test_report_status_fail_when_below_threshold(self):
        results = [
            {"detected": True, "final_action": "block", "wall_triggered": "wall1", "latency_ms": 5, "owasp_category": "LLM01", "attack_type": "direct"},
            *[{"detected": False, "final_action": "allow", "wall_triggered": None, "latency_ms": 5, "owasp_category": "LLM01", "attack_type": "direct"} for _ in range(9)],
        ]
        metrics = compute("run-1", results)
        report = generate("run-1", metrics, results)
        assert report["summary"]["status"] == "FAIL"
