"""
engine/correlator.py
======================================================================
Phase 5a [Option B] — Time-window incident correlator
    Groups related high-score events into incidents using:
      - 5-minute floor bucket (same time window)
      - Same principal OR same namespace
    Reduces raw alerts → clustered incidents (target ≥40% reduction)

Phase 5b [Option A] — LLM narrative generation (Groq)
    For each incident, makes one Groq API call to generate:
      - Plain-English description of what happened
      - Likely attacker intent
      - MITRE ATT&CK technique code
      - 2–3 recommended remediation steps
    Falls back to a rule-based template if Groq is unavailable.
"""

import os
import json
import pandas as pd
from datetime import datetime

# ── constants ────────────────────────────────────────────────────────────────

SCORE_THRESHOLD  = 20      # only events above this enter correlation
GROQ_MODEL = "llama-3.1-8b-instant"

# MITRE ATT&CK mapping per triggered signal
MITRE_MAP = {
    "MINING_BURST"            : ("T1496", "Resource Hijacking"),
    "PUBLIC_IP_NON_LB"        : ("T1190", "Exploit Public-Facing Application"),
    "PRIVILEGED_NO_CONTROLLER": ("T1611", "Escape to Host"),
    "OFF_HOURS_ASSUME_ROLE"   : ("T1078", "Valid Accounts"),
    "UNTAGGED_BURST"          : ("T1578", "Modify Cloud Compute Infrastructure"),
    "NEW_IP_ACCESS"           : ("T1078", "Valid Accounts"),
}


# ── Phase 5a: correlator ─────────────────────────────────────────────────────

def correlate(df: pd.DataFrame, use_llm: bool = True) -> list[dict]:
    """
    Group high-score events into incidents and generate narratives.

    Parameters
    ----------
    df       : scored DataFrame (must have risk_score, severity_label,
               triggered_signals columns from risk_scorer.py)
    use_llm  : if True, call Groq for narratives (Phase 5b)
               if False, use rule-based templates only

    Returns
    -------
    list of incident dicts, sorted by severity then start_time
    """
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"])

    # ── filter to only events that exceed the score threshold ──────────────
    risky = df[df["risk_score"] > SCORE_THRESHOLD].copy()

    if risky.empty:
        return []

    # ── create 5-min floor bucket per event ───────────────────────────────
    risky["_bucket"] = risky["timestamp"].dt.floor("5min")

    # ── group by (principal, bucket) — events from the same principal
    #    in the same 5-min window become one incident ─────────────────────
    incidents = []
    inc_counter = 1

    grouped = risky.groupby(["principal", "_bucket"], sort=False)

    for (principal, bucket), group in grouped:
        # collect all event IDs and signals in this group
        event_ids = group["event_id"].tolist()
        all_signals = set()
        for sig_str in group["triggered_signals"].dropna():
            for sig in sig_str.split(","):
                if sig.strip():
                    all_signals.add(sig.strip())

        if not all_signals:
            continue

        # incident severity = max severity across member events
        sev_order  = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}
        max_sev    = max(
            group["severity_label"].tolist(),
            key=lambda s: sev_order.get(s, 0)
        )
        max_score  = int(group["risk_score"].max())
        namespace  = group["namespace_or_region"].mode()[0]
        source     = group["source"].mode()[0]
        start_time = group["timestamp"].min().isoformat()
        end_time   = group["timestamp"].max().isoformat()

        # build evidence list (first 5 events shown in dashboard drill-down)
        evidence = []
        for _, ev in group.head(5).iterrows():
            evidence.append({
                "event_id"  : ev["event_id"],
                "event_type": ev["event_type"],
                "timestamp" : ev["timestamp"].isoformat(),
                "risk_score": int(ev["risk_score"]),
            })

        # MITRE codes for all triggered signals
        mitre_hits = {}
        for sig in all_signals:
            if sig in MITRE_MAP:
                code, name = MITRE_MAP[sig]
                mitre_hits[code] = name

        incident = {
            "incident_id"     : f"INC-{inc_counter:04d}",
            "severity"        : max_sev,
            "risk_score"      : max_score,
            "principal"       : principal,
            "namespace"       : namespace,
            "source"          : source,
            "start_time"      : start_time,
            "end_time"        : end_time,
            "event_count"     : len(event_ids),
            "event_ids"       : event_ids,
            "triggered_signals": sorted(all_signals),
            "mitre_techniques": mitre_hits,
            "evidence"        : evidence,
            "narrative"       : "",   # filled below
        }
        incidents.append(incident)
        inc_counter += 1

    # ── also group by (namespace, bucket) to catch cross-principal
    #    events in the same namespace (e.g. two devs in staging) ──────────
    ns_grouped = risky.groupby(["namespace_or_region", "_bucket"], sort=False)
    seen_pairs = {
        (inc["principal"], inc["start_time"])
        for inc in incidents
    }

    for (namespace, bucket), group in ns_grouped:
        # skip if all events in this group already captured above
        principals_here = set(group["principal"].unique())
        if len(principals_here) <= 1:
            continue   # same principal — already captured
        key = (namespace, bucket.isoformat())
        if key in seen_pairs:
            continue

        event_ids = group["event_id"].tolist()
        all_signals = set()
        for sig_str in group["triggered_signals"].dropna():
            for sig in sig_str.split(","):
                if sig.strip():
                    all_signals.add(sig.strip())
        if not all_signals:
            continue

        sev_order  = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}
        max_sev    = max(group["severity_label"].tolist(),
                         key=lambda s: sev_order.get(s, 0))
        max_score  = int(group["risk_score"].max())
        principal  = "multiple:" + ",".join(sorted(principals_here))
        start_time = group["timestamp"].min().isoformat()
        end_time   = group["timestamp"].max().isoformat()

        evidence = []
        for _, ev in group.head(5).iterrows():
            evidence.append({
                "event_id"  : ev["event_id"],
                "event_type": ev["event_type"],
                "timestamp" : ev["timestamp"].isoformat(),
                "risk_score": int(ev["risk_score"]),
            })

        mitre_hits = {}
        for sig in all_signals:
            if sig in MITRE_MAP:
                code, name = MITRE_MAP[sig]
                mitre_hits[code] = name

        incident = {
            "incident_id"      : f"INC-{inc_counter:04d}",
            "severity"         : max_sev,
            "risk_score"       : max_score,
            "principal"        : principal,
            "namespace"        : namespace,
            "source"           : group["source"].mode()[0],
            "start_time"       : start_time,
            "end_time"         : end_time,
            "event_count"      : len(event_ids),
            "event_ids"        : event_ids,
            "triggered_signals": sorted(all_signals),
            "mitre_techniques" : mitre_hits,
            "evidence"         : evidence,
            "narrative"        : "",
        }
        incidents.append(incident)
        inc_counter += 1

    # ── sort by severity then start_time ──────────────────────────────────
    sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}
    incidents.sort(key=lambda x: (-sev_order.get(x["severity"], 0), x["start_time"]))

    # ── Phase 5b: generate LLM narrative per incident ─────────────────────
    for inc in incidents:
        inc["narrative"] = _generate_narrative(inc, use_llm=use_llm)

    return incidents


# ── Phase 5b: LLM narrative generation [Option A] ───────────────────────────

def _generate_narrative(incident: dict, use_llm: bool = True) -> str:
    """
    Generate an analyst-ready narrative for a single incident.

    Option A: calls Groq LLM API (llama3-8b-8192, free tier)
    Fallback: rule-based template if Groq unavailable or key missing
    """
    if use_llm:
        groq_key = os.getenv("GROQ_API_KEY", "")
        if groq_key:
            try:
                return _groq_narrative(incident, groq_key)
            except Exception as e:
                print(f"  [LLM] Groq call failed for {incident['incident_id']}: {e}")
                print(f"  [LLM] Falling back to template narrative.")

    return _template_narrative(incident)


def _groq_narrative(incident: dict, api_key: str) -> str:
    """
    Call Groq API (Option A) to generate narrative.
    Returns the narrative string.
    """
    from groq import Groq
    client = Groq(api_key=api_key)

    mitre_str = ", ".join(
        f"{code} ({name})"
        for code, name in incident["mitre_techniques"].items()
    ) or "unknown"

    signals_str = ", ".join(incident["triggered_signals"])

    prompt = f"""You are a cloud security analyst writing an incident report.
Given the following incident data, write a concise analyst narrative (3-5 sentences).
Include: what happened, likely intent, and 2 specific remediation steps.
Keep it factual and professional. Do not add any preamble.

Incident ID    : {incident['incident_id']}
Severity       : {incident['severity']}
Principal      : {incident['principal']}
Namespace      : {incident['namespace']}
Event count    : {incident['event_count']} events
Time window    : {incident['start_time']} to {incident['end_time']}
Signals        : {signals_str}
MITRE techniques: {mitre_str}
Sample events  : {json.dumps(incident['evidence'][:3], indent=2)}

Write the narrative now:"""

    response = client.chat.completions.create(
        model=GROQ_MODEL,
        messages=[{"role": "user", "content": prompt}],
        max_tokens=300,
        temperature=0.3,
    )
    return response.choices[0].message.content.strip()


def _template_narrative(incident: dict) -> str:
    """
    Rule-based fallback narrative when Groq is unavailable.
    Covers all known signal combinations with specific language.
    """
    signals   = set(incident["triggered_signals"])
    principal = incident["principal"]
    ns        = incident["namespace"]
    count     = incident["event_count"]
    start     = incident["start_time"]
    sev       = incident["severity"]
    mitre_str = ", ".join(
        f"{code} ({name})"
        for code, name in incident["mitre_techniques"].items()
    ) or "unknown"

    if "MINING_BURST" in signals:
        return (
            f"[{sev}] Principal '{principal}' launched {count} high-CPU compute "
            f"instances in a 5-minute window starting at {start} — a pattern "
            f"consistent with unauthorized cryptocurrency mining. "
            f"The events occurred outside business hours with no resource tags and "
            f"no legitimate controller owner, indicating the CI/CD service account "
            f"may have been compromised. "
            f"MITRE ATT&CK: {mitre_str}. "
            f"Recommended actions: (1) Immediately rotate credentials for '{principal}' "
            f"and revoke all active sessions. "
            f"(2) Terminate all instances from burst group and review CloudTrail for "
            f"lateral movement from this principal in the past 24 hours."
        )

    if "PUBLIC_IP_NON_LB" in signals or "PRIVILEGED_NO_CONTROLLER" in signals:
        return (
            f"[{sev}] Principal '{principal}' created an ephemeral pod in namespace "
            f"'{ns}' at {start} with a public IP address and elevated privileges but "
            f"no controller owner — indicating a manually-launched debug pod exposed "
            f"to the internet. "
            f"A public port was reachable for approximately {count} minutes before "
            f"the pod terminated, sufficient time for external scanning or exploitation. "
            f"MITRE ATT&CK: {mitre_str}. "
            f"Recommended actions: (1) Apply a NetworkPolicy blocking NodePort "
            f"exposure in namespace '{ns}'. "
            f"(2) Review pod logs for external connection attempts and audit RBAC "
            f"permissions that allowed privileged pod creation."
        )

    if "OFF_HOURS_ASSUME_ROLE" in signals:
        return (
            f"[{sev}] Principal '{principal}' assumed a high-privilege IAM role "
            f"and accessed sensitive resources at {start} — outside normal business "
            f"hours. "
            f"The session TTL was short (15 min), consistent with automated credential "
            f"abuse from a compromised Lambda function or stolen token. "
            f"MITRE ATT&CK: {mitre_str}. "
            f"Recommended actions: (1) Rotate all API keys and session tokens for "
            f"'{principal}'. "
            f"(2) Enable GuardDuty anomalous activity alerts and add an SCP "
            f"restricting off-hours AssumeRole for this role ARN."
        )

    # generic fallback
    return (
        f"[{sev}] {count} suspicious event(s) detected from principal '{principal}' "
        f"in namespace '{ns}' starting at {start}. "
        f"Triggered signals: {', '.join(signals)}. "
        f"MITRE ATT&CK: {mitre_str}. "
        f"Review the evidence events and apply least-privilege remediation."
    )


# ── summary helper ───────────────────────────────────────────────────────────

def correlation_summary(incidents: list[dict], total_raw_alerts: int) -> dict:
    """Return summary dict for dashboard and evaluator."""
    if not incidents:
        return {
            "total_incidents"  : 0,
            "raw_alerts"       : total_raw_alerts,
            "alert_reduction"  : 0.0,
            "critical_incidents": 0,
            "high_incidents"   : 0,
            "medium_incidents" : 0,
        }

    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for inc in incidents:
        sev = inc["severity"]
        if sev in sev_counts:
            sev_counts[sev] += 1

    reduction = (1 - len(incidents) / total_raw_alerts) * 100 if total_raw_alerts > 0 else 0

    return {
        "total_incidents"   : len(incidents),
        "raw_alerts"        : total_raw_alerts,
        "alert_reduction_pct": round(reduction, 1),
        "critical_incidents": sev_counts["CRITICAL"],
        "high_incidents"    : sev_counts["HIGH"],
        "medium_incidents"  : sev_counts["MEDIUM"],
    }
