import pytest
import asyncio
from app.telemetry.lab import EvaluationLabRunner, EVALUATION_RUN_STORE

def test_full_evaluation_benchmark_execution():
    run = asyncio.run(EvaluationLabRunner.run_full_benchmark(
        model_name="test-ai-provider-v1"
    ))

    # Verify run identifier & configuration
    assert run.runId.startswith("eval-run-")
    assert run.model == "test-ai-provider-v1"
    assert run.configuration["mode"] == "AUTONOMOUS"

    # Verify scenario results (all 8 scenarios evaluated)
    assert len(run.scenarioResults) == 8
    sc_ids = [r.scenarioId for r in run.scenarioResults]
    assert "ssh-bruteforce" in sc_ids
    assert "credential-compromise" in sc_ids
    assert "privilege-escalation" in sc_ids
    assert "network-recon" in sc_ids
    assert "suspicious-dns" in sc_ids
    assert "post-login-exec" in sc_ids
    assert "lateral-movement" in sc_ids
    assert "suspicious-exfil" in sc_ids

    # Verify calculated overall metrics bounds
    m = run.overallMetrics
    assert 0.0 <= m.detectionRatePercent <= 100.0
    assert 0.0 <= m.averagePrecision <= 1.0
    assert 0.0 <= m.averageRecall <= 1.0
    assert 0.0 <= m.falsePositiveRatePercent <= 100.0
    assert 0.0 <= m.falseNegativeRatePercent <= 100.0
    assert 0.0 <= m.evidenceCoveragePercent <= 100.0
    assert 0.0 <= m.toolEfficiencyPercent <= 100.0
    assert m.averageInvestigationSteps > 0
    assert m.averageToolCalls > 0
    assert m.averageTimeToFindingMs > 0

    # Verify run stored for reproducibility comparison
    assert run.runId in EVALUATION_RUN_STORE
