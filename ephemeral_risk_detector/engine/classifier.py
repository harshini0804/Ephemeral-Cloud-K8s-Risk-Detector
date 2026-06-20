"""
engine/classifier.py   [Option B — Heuristic ephemeral classification]
======================================================================
Classifies every event row as ephemeral vs persistent using four
heuristic rules. No ML model is used here — Option B deliberately
uses deterministic logic so results are fully explainable to auditors.

Adds three columns to the events DataFrame:
    is_ephemeral        bool    True if the resource is short-lived
    ephemeral_type      str     job_pod | spot | lambda | ci_runner |
                                unmanaged | persistent
    ephemeral_confidence float  0.0 – 1.0 (how confident the classifier is)

Rules applied in order (first match wins):
    Rule 1 — Known ephemeral resource types  (confidence 1.0)
    Rule 2 — TTL threshold < 60 minutes      (confidence 0.85)
    Rule 3 — No controller owner on K8s pod  (confidence 0.75)
    Rule 4 — Missing required tags           (confidence 0.60)
    Default — persistent                     (confidence 1.0)
"""

import pandas as pd


# ── constants ────────────────────────────────────────────────────────────────

# Resource types that are always ephemeral by nature
ALWAYS_EPHEMERAL_TYPES = {
    "spot-instance", "job-pod", "lambda", "ci-runner",
    "debug-pod", "iam-session", "privileged-pod",
}

# TTL below which a resource is considered ephemeral
EPHEMERAL_TTL_THRESHOLD = 60.0  # minutes

# K8s controller owners that indicate a managed (legitimate) pod
MANAGED_CONTROLLERS = {"HPA", "Deployment", "Job", "CronJob", "StatefulSet",
                        "DaemonSet", "ReplicaSet", "AutoScaling"}


# ── main classifier function ─────────────────────────────────────────────────

def classify(df: pd.DataFrame) -> pd.DataFrame:
    """
    Apply all four heuristic rules to the events DataFrame.
    Returns the same DataFrame with three new columns added.

    Parameters
    ----------
    df : pd.DataFrame
        Combined events DataFrame (cloud + k8s + iam rows).

    Returns
    -------
    pd.DataFrame
        Same rows, three new columns appended.
    """
    df = df.copy()

    # initialise output columns
    df["is_ephemeral"]         = False
    df["ephemeral_type"]       = "persistent"
    df["ephemeral_confidence"] = 1.0

    for idx, row in df.iterrows():
        etype, conf = _classify_row(row)
        df.at[idx, "is_ephemeral"]         = (etype != "persistent")
        df.at[idx, "ephemeral_type"]       = etype
        df.at[idx, "ephemeral_confidence"] = conf

    return df


def _classify_row(row: pd.Series) -> tuple[str, float]:
    """
    Apply rules in priority order. Returns (ephemeral_type, confidence).
    """

    # ── Rule 1: Known ephemeral resource types ─────────────────────────────
    # Lambda invocations, spot instances, job pods are always ephemeral
    # regardless of any other field.
    rtype = str(row.get("resource_type", "")).lower()
    if rtype in ALWAYS_EPHEMERAL_TYPES:
        return _map_resource_type(rtype), 1.0

    # ── Rule 2: TTL threshold ──────────────────────────────────────────────
    # Resources that lived less than 60 minutes are ephemeral.
    # (also catches debug pods and short-lived spot instances not caught by R1)
    ttl = row.get("ttl_minutes", None)
    if ttl is not None and not pd.isna(ttl) and float(ttl) < EPHEMERAL_TTL_THRESHOLD:
        return "short_lived", 0.85

    # ── Rule 3: No controller owner on K8s pod ─────────────────────────────
    # A K8s pod without a controller owner was not created by a Deployment
    # or Job — it was launched manually. This is suspicious for ephemeral
    # workloads and gets its own type so the scorer can weigh it heavily.
    if row.get("source") == "k8s":
        owner = row.get("controller_owner", None)
        if pd.isna(owner) or str(owner).strip() in ("", "None", "nan"):
            return "unmanaged", 0.75

    # ── Rule 4: Missing required tags ─────────────────────────────────────
    # An ephemeral resource with no cost-centre / team / env tags is
    # harder to attribute and clean up — flag it as untagged_ephemeral.
    tags = row.get("tags_present", True)
    if not tags:
        return "untagged_ephemeral", 0.60

    # ── Default: persistent ────────────────────────────────────────────────
    return "persistent", 1.0


def _map_resource_type(rtype: str) -> str:
    """Map raw resource_type string to a clean ephemeral_type label."""
    mapping = {
        "spot-instance" : "spot",
        "job-pod"       : "job_pod",
        "ci-runner"     : "ci_runner",
        "debug-pod"     : "debug_pod",
        "lambda"        : "lambda",
        "iam-session"   : "iam_session",
        "privileged-pod": "privileged_pod",
    }
    return mapping.get(rtype, "ephemeral")


# ── summary helper ───────────────────────────────────────────────────────────

def classification_summary(df: pd.DataFrame) -> dict:
    """Return a summary dict of classification results for the dashboard."""
    if "is_ephemeral" not in df.columns:
        df = classify(df)

    total     = len(df)
    ephemeral = df["is_ephemeral"].sum()
    by_type   = df["ephemeral_type"].value_counts().to_dict()

    return {
        "total_events"      : int(total),
        "ephemeral_count"   : int(ephemeral),
        "persistent_count"  : int(total - ephemeral),
        "ephemeral_pct"     : round(ephemeral / total * 100, 1),
        "by_type"           : by_type,
    }
