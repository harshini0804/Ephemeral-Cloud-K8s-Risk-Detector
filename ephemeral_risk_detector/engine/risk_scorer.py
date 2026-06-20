"""
engine/risk_scorer.py   [Option B — Statistical risk signal detection]
======================================================================
Detects risk signals per event and computes a weighted risk score using
Z-score and IQR statistical baselines per namespace/principal.

Key Option B feature: Z-score baselines mean a principal that always
creates 40 pods (HPA) won't be flagged, but one that spikes from 2 to
20 will be — same burst size, different context.

Adds columns: risk_score, severity_label, triggered_signals, z_score
"""

import pandas as pd
import numpy as np
from scipy import stats

# ── risk signal definitions ──────────────────────────────────────────────────

SIGNALS = {
    "MINING_BURST": {
        "weight": 60, "severity": "CRITICAL",
        "description": "Bulk compute creation at unusual hour — crypto-mining pattern",
    },
    "PUBLIC_IP_NON_LB": {
        "weight": 30, "severity": "HIGH",
        "description": "Public IP on ephemeral pod with no load-balancer controller",
    },
    "PRIVILEGED_NO_CONTROLLER": {
        "weight": 25, "severity": "HIGH",
        "description": "Privileged pod without a controller owner",
    },
    "OFF_HOURS_ASSUME_ROLE": {
        "weight": 22, "severity": "MEDIUM",
        "description": "High-privilege IAM role assumed outside business hours",
    },
    "UNTAGGED_BURST": {
        "weight": 15, "severity": "MEDIUM",
        "description": "Untagged burst of events from same principal",
    },
    "NEW_IP_ACCESS": {
        "weight": 10, "severity": "LOW",
        "description": "IAM session from previously unseen IP",
    },
}

# Score → severity (adjusted so common combos land in right tier)
SEVERITY_THRESHOLDS = [
    (65, "CRITICAL"),
    (45, "HIGH"),
    (20, "MEDIUM"),
    (10, "LOW"),
    (0,  "NONE"),
]

BUSINESS_HOUR_START     = 7
BUSINESS_HOUR_END       = 21
MINING_INSTANCE_PREFIXES = ("c5", "c4", "c6", "g4", "p3", "p4")
BURST_COUNT_THRESHOLD   = 10    # events from same principal in 5-min bucket
ZSCORE_THRESHOLD        = 2.0
IQR_SHORT_TTL_MULT      = 1.3
MANAGED_CONTROLLERS     = {
    "HPA", "Deployment", "Job", "CronJob",
    "StatefulSet", "DaemonSet", "ReplicaSet", "AutoScaling",
}


# ── public entry point ───────────────────────────────────────────────────────

def score(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"])

    # Step 1 — compute burst counts using 5-min floor buckets (O(n log n))
    df = _add_burst_counts(df)

    # Step 2 — Z-scores per principal on bucket-level counts
    df = _add_zscores(df)

    # Step 3 — IQR TTL bounds per resource type
    ttl_bounds = _compute_ttl_bounds(df)

    # Step 4 — score each row
    results = df.apply(lambda row: _score_row(row, ttl_bounds), axis=1)
    df["risk_score"]        = results.apply(lambda x: x[0])
    df["severity_label"]    = results.apply(lambda x: x[1])
    df["triggered_signals"] = results.apply(lambda x: x[2])
    return df


# ── burst count: 5-min floor bucket approach ─────────────────────────────────

def _add_burst_counts(df: pd.DataFrame) -> pd.DataFrame:
    """
    Count total events per (principal, 10-min bucket).
    Using 10-min windows avoids missing burst events that straddle a
    5-min boundary (e.g. a 20-event burst starting at 03:14 would split
    across the 03:10 and 03:15 buckets in a 5-min scheme).
    Every event in the same bucket sees the same total count.
    """
    df = df.sort_values("timestamp").copy()
    df["_time_bucket"] = df["timestamp"].dt.floor("10min")
    bucket_counts = (
        df.groupby(["principal", "_time_bucket"])
        .size()
        .reset_index(name="burst_count_5min")
    )
    df = df.merge(bucket_counts, on=["principal", "_time_bucket"], how="left")
    df.drop(columns=["_time_bucket"], inplace=True)
    return df


# ── Z-score: per principal on bucket-level burst counts ──────────────────────

def _add_zscores(df: pd.DataFrame) -> pd.DataFrame:
    """
    Compute Z-score of burst_count_5min per principal.
    HPA (always 40 pods) gets mean≈40, std>0, so Z≈0 — suppressed.
    Attacker (normally 2, burst 20) gets high Z → flagged.
    """
    df["z_score"] = 0.0
    for principal, group in df.groupby("principal"):
        counts = group["burst_count_5min"].values
        if len(counts) < 3 or counts.std(ddof=1) == 0:
            continue
        z = stats.zscore(counts, ddof=1)
        df.loc[group.index, "z_score"] = z
    return df


# ── IQR TTL bounds ───────────────────────────────────────────────────────────

def _compute_ttl_bounds(df: pd.DataFrame) -> dict:
    bounds = {}
    for rtype, group in df.groupby("resource_type"):
        ttls = group["ttl_minutes"].dropna()
        if len(ttls) < 4:
            bounds[rtype] = 0.0
            continue
        q1  = ttls.quantile(0.25)
        q3  = ttls.quantile(0.75)
        iqr = q3 - q1
        bounds[rtype] = max(0.0, q1 - 1.5 * iqr)
    return bounds


# ── per-row scoring ──────────────────────────────────────────────────────────

def _score_row(row: pd.Series, ttl_bounds: dict) -> tuple[int, str, str]:
    # ── derive fields ──────────────────────────────────────────────────────
    owner       = str(row.get("controller_owner") or "").strip()
    tagged      = bool(row.get("tags_present", False))
    hour        = int(row.get("hour_of_day", 12))
    source      = str(row.get("source", ""))
    event_type  = str(row.get("event_type", ""))
    burst_count = int(row.get("burst_count_5min", 0))
    z_score     = float(row.get("z_score", 0.0))
    public_ip   = row.get("public_ip", None)
    privileged  = bool(row.get("privileged", False))
    sensitive   = bool(row.get("sensitive_resource", False))
    inst_type   = str(row.get("instance_type") or "")
    ttl         = float(row.get("ttl_minutes") or 60)
    rtype       = str(row.get("resource_type", ""))

    is_managed  = owner in MANAGED_CONTROLLERS
    in_hours    = BUSINESS_HOUR_START <= hour <= BUSINESS_HOUR_END
    is_off_hours= not in_hours

    # ── legit autoscale suppression (Option B) ─────────────────────────────
    # Managed controller + tagged + business hours → always 0
    if is_managed and tagged and in_hours:
        return 0, "NONE", ""

    triggered  = []
    raw_score  = 0

    # ── Signal 1: MINING_BURST ─────────────────────────────────────────────
    is_mining_inst  = inst_type.startswith(MINING_INSTANCE_PREFIXES)
    is_stat_anomaly = (z_score > ZSCORE_THRESHOLD or
                       burst_count > BURST_COUNT_THRESHOLD)
    if (source == "cloud" and
            event_type == "RunInstances" and
            is_off_hours and
            is_mining_inst and
            is_stat_anomaly and
            not tagged):
        triggered.append("MINING_BURST")
        raw_score += SIGNALS["MINING_BURST"]["weight"]

    # ── Signal 2: PUBLIC_IP_NON_LB ─────────────────────────────────────────
    has_public_ip = (public_ip is not None and
                     str(public_ip).strip() not in ("", "None", "nan"))
    if source == "k8s" and has_public_ip and not is_managed:
        triggered.append("PUBLIC_IP_NON_LB")
        raw_score += SIGNALS["PUBLIC_IP_NON_LB"]["weight"]

    # ── Signal 3: PRIVILEGED_NO_CONTROLLER ────────────────────────────────
    no_controller = owner in ("", "None", "nan", "NaN")
    if source == "k8s" and privileged and no_controller:
        triggered.append("PRIVILEGED_NO_CONTROLLER")
        raw_score += SIGNALS["PRIVILEGED_NO_CONTROLLER"]["weight"]

    # ── Signal 4: OFF_HOURS_ASSUME_ROLE ───────────────────────────────────
    if (source == "iam" and
            event_type == "AssumeRole" and
            is_off_hours and
            sensitive):
        triggered.append("OFF_HOURS_ASSUME_ROLE")
        raw_score += SIGNALS["OFF_HOURS_ASSUME_ROLE"]["weight"]

    # ── Signal 5: UNTAGGED_BURST ──────────────────────────────────────────
    if not tagged and is_stat_anomaly and not is_managed and burst_count > 5:
        triggered.append("UNTAGGED_BURST")
        raw_score += SIGNALS["UNTAGGED_BURST"]["weight"]

    # ── IQR TTL multiplier ─────────────────────────────────────────────────
    lower_fence = ttl_bounds.get(rtype, 0.0)
    if ttl < lower_fence and raw_score > 0:
        raw_score = int(raw_score * IQR_SHORT_TTL_MULT)

    # ── Exposure window multiplier ─────────────────────────────────────────
    if raw_score > 0:
        raw_score = int(raw_score * (1.2 if ttl > 120 else 1.1 if ttl > 30 else 1.0))

    final_score = min(100, max(0, raw_score))

    # ── Severity — signal override for MINING_BURST ────────────────────────
    # A confirmed crypto-mining burst is always CRITICAL regardless of score
    if "MINING_BURST" in triggered:
        severity = "CRITICAL"
    else:
        severity = "NONE"
        for threshold, label in SEVERITY_THRESHOLDS:
            if final_score >= threshold:
                severity = label
                break

    return final_score, severity, ",".join(triggered)


# ── summary helper ───────────────────────────────────────────────────────────

def scoring_summary(df: pd.DataFrame) -> dict:
    return {
        "total_scored"        : int(len(df)),
        "critical_count"      : int((df["severity_label"] == "CRITICAL").sum()),
        "high_count"          : int((df["severity_label"] == "HIGH").sum()),
        "medium_count"        : int((df["severity_label"] == "MEDIUM").sum()),
        "low_count"           : int((df["severity_label"] == "LOW").sum()),
        "none_count"          : int((df["severity_label"] == "NONE").sum()),
        "top_risky_principal" : (
            df[df["risk_score"] > 0]
            .groupby("principal")["risk_score"].sum()
            .idxmax() if (df["risk_score"] > 0).any() else "none"
        ),
    }
