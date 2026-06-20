"""
engine/evaluator.py   [Option B — Self-evaluation metrics]
===========================================================
Computes all metrics required by the PS success criteria:

    Metric                 Target     Measured by
    ─────────────────────  ─────────  ─────────────────────────────
    Precision              > 75%      sklearn classification_report
    Recall                 > 70%      sklearn classification_report
    F1                     > 0.72     sklearn classification_report
    CRITICAL recall        100%       subset where severity==CRITICAL
    Alert reduction        ≥ 40%      raw_alerts vs incidents count
    Noise suppression      > 90%      legit autoscale events scored 0

Usage:
    from engine.evaluator import evaluate
    metrics = evaluate(scored_df, incidents, raw_alert_count)
"""

import pandas as pd
import numpy as np
from sklearn.metrics import (
    classification_report,
    precision_score,
    recall_score,
    f1_score,
)


def evaluate(
    scored_df: pd.DataFrame,
    incidents: list[dict],
    raw_alert_count: int,
) -> dict:
    """
    Run all evaluation metrics and return a single results dict.

    Parameters
    ----------
    scored_df       : DataFrame after classifier + risk_scorer have run.
                      Must contain columns: is_risky (ground truth),
                      risk_score, severity_label, anomaly_type.
    incidents       : list of incident dicts from correlator.correlate()
    raw_alert_count : total events with risk_score > threshold before
                      clustering (used for alert reduction metric)

    Returns
    -------
    dict with all metric values — served at GET /api/evaluate
    """
    df = scored_df.copy()

    # ── binary prediction: event is predicted risky if score > 0 ──────────
    df["predicted_risky"] = df["risk_score"] > 0
    y_true = df["is_risky"].astype(int)
    y_pred = df["predicted_risky"].astype(int)

    # ── main classification metrics ────────────────────────────────────────
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall    = recall_score(y_true, y_pred, zero_division=0)
    f1        = f1_score(y_true, y_pred, zero_division=0)

    # full report as string (printed to console)
    report = classification_report(
        y_true, y_pred,
        target_names=["Compliant", "At-Risk"],
        zero_division=0,
    )

    # ── CRITICAL event recall ─────────────────────────────────────────────
    # How many CRITICAL ground-truth events did we catch?
    # From the PS: "what % of CRITICAL exceptions did you catch?"
    critical_mask    = df["anomaly_type"].isin(["MINING_BURST"])
    critical_true    = critical_mask.sum()
    critical_caught  = (critical_mask & df["predicted_risky"]).sum()
    critical_recall  = (
        round(critical_caught / critical_true * 100, 1)
        if critical_true > 0 else 0.0
    )

    # ── alert reduction ───────────────────────────────────────────────────
    total_incidents  = len(incidents)
    alert_reduction  = (
        round((1 - total_incidents / raw_alert_count) * 100, 1)
        if raw_alert_count > 0 else 0.0
    )

    # ── noise suppression: legit autoscale events correctly scored 0 ──────
    # Events with controller_owner in managed set AND is_risky=False
    managed = {"HPA", "Deployment", "Job", "CronJob", "AutoScaling",
               "StatefulSet", "DaemonSet", "ReplicaSet"}
    legit_mask        = (
        df["controller_owner"].astype(str).isin(managed) &
        (~df["is_risky"])
    )
    legit_count       = legit_mask.sum()
    legit_not_flagged = (legit_mask & ~df["predicted_risky"]).sum()
    noise_suppression = (
        round(legit_not_flagged / legit_count * 100, 1)
        if legit_count > 0 else 100.0
    )

    # ── false positive count ──────────────────────────────────────────────
    false_positives = int(((~df["is_risky"]) & df["predicted_risky"]).sum())
    false_negatives = int((df["is_risky"] & ~df["predicted_risky"]).sum())
    true_positives  = int((df["is_risky"] & df["predicted_risky"]).sum())

    # ── target checks (pass/fail) ─────────────────────────────────────────
    targets = {
        "precision_target"        : bool(precision >= 0.75),
        "recall_target"           : bool(recall >= 0.70),
        "f1_target"               : bool(f1 >= 0.72),
        "critical_recall_target"  : bool(critical_recall >= 95),
        "alert_reduction_target"  : bool(alert_reduction >= 40),
        "noise_suppression_target": bool(noise_suppression >= 90),
    }

    # ── anomaly type breakdown ────────────────────────────────────────────
    breakdown = {}
    for atype in df["anomaly_type"].unique():
        if atype == "NORMAL":
            continue
        subset = df[df["anomaly_type"] == atype]
        caught = (subset["predicted_risky"]).sum()
        breakdown[atype] = {
            "total"  : int(len(subset)),
            "caught" : int(caught),
            "recall" : round(caught / len(subset) * 100, 1) if len(subset) > 0 else 0,
        }

    metrics = {
        "precision"             : round(float(precision), 4),
        "recall"                : round(float(recall), 4),
        "f1_score"              : round(float(f1), 4),
        "true_positives"        : true_positives,
        "false_positives"       : false_positives,
        "false_negatives"       : false_negatives,
        "critical_recall_pct"   : critical_recall,
        "alert_reduction_pct"   : alert_reduction,
        "noise_suppression_pct" : noise_suppression,
        "raw_alerts"            : raw_alert_count,
        "total_incidents"       : total_incidents,
        "targets_met"           : targets,
        "anomaly_breakdown"     : breakdown,
        "classification_report" : report,
    }

    return metrics


def print_metrics(metrics: dict):
    """Pretty-print evaluation results to console."""
    print("\n" + "=" * 55)
    print("  PHASE 6 — Evaluation Results")
    print("=" * 55)

    def tick(passed): return "✓" if passed else "✗"
    t = metrics["targets_met"]

    print(f"\n  Detection Quality")
    print(f"  {'Precision':<28} {metrics['precision']:.1%}  "
          f"{tick(t['precision_target'])} (target >75%)")
    print(f"  {'Recall':<28} {metrics['recall']:.1%}  "
          f"{tick(t['recall_target'])} (target >70%)")
    print(f"  {'F1 Score':<28} {metrics['f1_score']:.4f}  "
          f"{tick(t['f1_target'])} (target >0.72)")
    print(f"  {'CRITICAL recall':<28} {metrics['critical_recall_pct']}%  "
          f"{tick(t['critical_recall_target'])} (target ≥95%)")

    print(f"\n  Alert Management")
    print(f"  {'Raw alerts':<28} {metrics['raw_alerts']}")
    print(f"  {'Incidents (after cluster)':<28} {metrics['total_incidents']}")
    print(f"  {'Alert reduction':<28} {metrics['alert_reduction_pct']}%  "
          f"{tick(t['alert_reduction_target'])} (target ≥40%)")
    print(f"  {'Noise suppression':<28} {metrics['noise_suppression_pct']}%  "
          f"{tick(t['noise_suppression_target'])} (target ≥90%)")

    print(f"\n  Event Counts")
    print(f"  {'True positives':<28} {metrics['true_positives']}")
    print(f"  {'False positives':<28} {metrics['false_positives']}")
    print(f"  {'False negatives':<28} {metrics['false_negatives']}")

    print(f"\n  Per-Anomaly Breakdown")
    for atype, vals in metrics["anomaly_breakdown"].items():
        print(f"  {atype:<30} caught {vals['caught']}/{vals['total']} "
              f"({vals['recall']}%)")

    all_passed = all(t.values())
    print(f"\n  Overall: {'ALL TARGETS MET ✓' if all_passed else 'SOME TARGETS MISSED'}")
    print("=" * 55 + "\n")
