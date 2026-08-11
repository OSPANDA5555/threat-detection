from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from app.schemas.finding import Finding
from app.schemas.evidence import Evidence
from .models import GroundTruth, EvaluationReport

class EvaluationEngine:
    """
    Evaluates AI-generated threat findings against hidden scenario ground truth.
    Provides quantitative metrics for SOC benchmark assessment.
    """

    @staticmethod
    def evaluate_finding(finding: Finding, evidence_list: List[Evidence], ground_truth: GroundTruth) -> EvaluationReport:
        """
        Compare AI Finding + Evidence citations against ground truth metadata.
        """
        # 1. Evaluate MITRE ATT&CK Technique Match
        expected_techs = set(t.upper() for t in ground_truth.expectedTechniques)
        found_techs = set(t.upper() for t in finding.mitreTechniques)

        matched_techs = list(expected_techs.intersection(found_techs))
        missing_techs = list(expected_techs.difference(found_techs))
        extra_techs = list(found_techs.difference(expected_techs))

        # 2. Evaluate Host & Attacker IP Match
        host_match = any(ground_truth.affectedHost.lower() in h.lower() for h in finding.affectedHosts)
        ip_match = any(ground_truth.attackerIp in ip for ip in finding.sourceIps)

        # 3. Evidence Coverage Calculation
        ground_truth_eids = set(ground_truth.groundTruthEventIds)
        cited_eids = set(finding.evidenceIds)

        # Map cited evidence IDs to raw reference event IDs if applicable
        raw_eids = set()
        for evd in evidence_list:
            if evd.id in cited_eids:
                raw_eids.add(evd.id)
                # Check if normalized data or raw ref contains event ID
                for gtid in ground_truth_eids:
                    if gtid in str(evd.normalizedData) or gtid in evd.rawReference or gtid in evd.id:
                        raw_eids.add(gtid)

        matched_eids = ground_truth_eids.intersection(raw_eids)
        coverage_percent = (len(matched_eids) / max(len(ground_truth_eids), 1)) * 100.0

        # 4. Precision & Recall Computation
        tp = len(matched_techs) + (1 if host_match else 0) + (1 if ip_match else 0)
        fp = len(extra_techs) + (0 if host_match else 1) + (0 if ip_match else 1)
        fn = len(missing_techs)

        precision = tp / max(tp + fp, 1)
        recall = tp / max(tp + fn, 1)
        f1 = (2 * precision * recall) / max(precision + recall, 0.0001)

        is_accurate = host_match and len(matched_techs) > 0 and precision >= 0.5 and recall >= 0.5

        notes = []
        if host_match:
          notes.append(f"✓ Affected host '{ground_truth.affectedHost}' correctly identified.")
        else:
          notes.append(f"✗ Failed to identify affected host '{ground_truth.affectedHost}'.")

        if ip_match:
          notes.append(f"✓ Attacker IP '{ground_truth.attackerIp}' correctly identified.")
        else:
          notes.append(f"✗ Attacker IP '{ground_truth.attackerIp}' missing.")

        if matched_techs:
          notes.append(f"✓ Matched techniques: {', '.join(matched_techs)}")

        return EvaluationReport(
            scenarioId=ground_truth.scenarioId,
            evaluatedAt=datetime.now(timezone.utc).isoformat(),
            precision=round(precision, 2),
            recall=round(recall, 2),
            f1Score=round(f1, 2),
            falsePositivesCount=fp,
            falseNegativesCount=fn,
            evidenceCoveragePercent=round(coverage_percent, 1),
            matchedTechniques=matched_techs,
            missingTechniques=missing_techs,
            isAccurate=is_accurate,
            summaryNotes=" ".join(notes)
        )
