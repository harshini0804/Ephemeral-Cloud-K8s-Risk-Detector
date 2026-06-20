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
GROQ_MODEL       = "llama3-8b-8192"

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
            "narrative"        : "",
            "narrative_source" : "",
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
        narrative_text, narrative_src = _generate_narrative(inc, use_llm=use_llm)
        inc["narrative"] = narrative_text
        inc["narrative_source"] = narrative_src

    return incidents


# ── Phase 5b: LLM narrative generation [Option A] ───────────────────────────

def _readable_time(iso_str: str) -> str:
    """Convert ISO timestamp to human-readable format. Cross-platform safe."""
    try:
        dt = datetime.fromisoformat(iso_str)
        hour    = dt.hour % 12 or 12
        minute  = dt.strftime("%M")
        period  = "AM" if dt.hour < 12 else "PM"
        return dt.strftime(f"%B %d, %Y, at ~{hour}:{minute} {period} UTC")
    except Exception:
        return iso_str


def _generate_narrative(incident: dict, use_llm: bool = True) -> tuple[str, str]:
    """
    Generate a human-readable analyst narrative for a single incident.

    Returns (narrative_text, source) where source is 'llm' or 'template'.
    Option A  : Groq LLM API call using the structured template prompt.
    Fallback  : Rule-based template matching the same bullet-point format.
    """
    if use_llm:
        groq_key = os.getenv("GROQ_API_KEY", "")
        if groq_key:
            try:
                return _groq_narrative(incident, groq_key), "llm"
            except Exception as e:
                print(f"  [LLM] Groq call failed for {incident['incident_id']}: {e}")
                print(f"  [LLM] Falling back to template narrative.")

    return _template_narrative(incident), "template"


def _groq_narrative(incident: dict, api_key: str) -> str:
    """
    Call Groq API [Option A].
    Instructs the model to fill in the user-defined structured template
    so the output is always readable, consistent, and non-technical.
    """
    from groq import Groq
    client = Groq(api_key=api_key)

    mitre_str   = ", ".join(
        f"{code} ({name})" for code, name in incident["mitre_techniques"].items()
    ) or "unknown"
    signals_str = ", ".join(incident["triggered_signals"])
    time_str    = _readable_time(incident["start_time"])

    # Raw log passed to the model so it has all the facts to fill in
    raw_log = f"""Incident ID   : {incident['incident_id']}
Severity      : {incident['severity']}
Risk Score    : {incident['risk_score']}/100
Principal     : {incident['principal']}
Namespace     : {incident['namespace']}
Source        : {incident['source']}
Event count   : {incident['event_count']} events
Start time    : {time_str}
End time      : {_readable_time(incident['end_time'])}
Signals       : {signals_str}
MITRE         : {mitre_str}
Sample events : {json.dumps(incident['evidence'][:3], indent=2)}"""

    prompt = f"""You are a cloud security analyst writing a plain-English incident brief for a non-technical audience.

Fill in the template below using ONLY the facts from the Raw Incident Log. 
Replace every bracketed instruction with real content. 
Do NOT add any preamble, explanation, or extra text outside the template.
Output ONLY the filled template, nothing else.

### TEMPLATE START ###
* **When:** [Date and time in the format: "Month DD, YYYY, at ~H:MM AM/PM UTC"]
* **Where/Who:** [namespace or region] via the `[principal name]` account
* **What Happened:** [Summarise the number and type of events in plain English, e.g. "15 suspicious RunInstances commands were fired in under 4 minutes using high-CPU instance types, all without resource tags."]
* **The Threat:** [One sentence explaining the likely attack in plain English, e.g. "This is consistent with unauthorised cryptocurrency mining using compromised cloud credentials."] (Risk Score: {incident['risk_score']}/100). Matches MITRE tactics for [MITRE technique IDs and names from the log].
* **Action Required:**
  1. **Immediate:** [Most urgent single action, specific to this incident]
  2. **Follow-up:** [Secondary investigative or preventive action]
### TEMPLATE END ###

Raw Incident Log:
{raw_log}

Fill in the template now:"""

    response = client.chat.completions.create(
        model=GROQ_MODEL,
        messages=[{"role": "user", "content": prompt}],
        max_tokens=420,
        temperature=0.2,   # lower temp = more consistent structure
    )
    return response.choices[0].message.content.strip()


def _template_narrative(incident: dict) -> str:
    """
    Rule-based fallback — same bullet-point format as the Groq template
    so LLM and template outputs look visually identical in the dashboard.
    """
    signals   = set(incident["triggered_signals"])
    principal = incident["principal"]
    ns        = incident["namespace"]
    count     = incident["event_count"]
    score     = incident["risk_score"]
    time_str  = _readable_time(incident["start_time"])
    mitre_str = ", ".join(
        f"{code} ({name})" for code, name in incident["mitre_techniques"].items()
    ) or "unknown"

    if "MINING_BURST" in signals:
        return (
            f"* **When:** {time_str}\n"
            f"* **Where/Who:** `{ns}` region, via the `{principal}` account\n"
            f"* **What Happened:** {count} unauthorized `RunInstances` commands were "
            f"fired in under 5 minutes using high-CPU instance types (c5/c4/g4), "
            f"all outside business hours with no resource tags and no legitimate "
            f"controller owner.\n"
            f"* **The Threat:** This is consistent with unauthorized cryptocurrency "
            f"mining using a compromised CI/CD service account. "
            f"(Risk Score: {score}/100). Matches MITRE tactics for {mitre_str}.\n"
            f"* **Action Required:**\n"
            f"  1. **Immediate:** Rotate credentials for `{principal}`, revoke all "
            f"active sessions, and terminate every instance launched in this burst.\n"
            f"  2. **Follow-up:** Review CloudTrail logs for lateral movement from "
            f"this account over the past 24 hours and restrict `RunInstances` "
            f"permissions to approved instance types only."
        )

    if "PUBLIC_IP_NON_LB" in signals or "PRIVILEGED_NO_CONTROLLER" in signals:
        return (
            f"* **When:** {time_str}\n"
            f"* **Where/Who:** `{ns}` namespace, via the `{principal}` account\n"
            f"* **What Happened:** A privileged Kubernetes pod with no controller "
            f"owner was launched with a public IP address — manually created and "
            f"directly exposed to the internet without load-balancer protection.\n"
            f"* **The Threat:** This is consistent with an unsecured debug pod that "
            f"could be found and exploited by external scanners within minutes. "
            f"(Risk Score: {score}/100). Matches MITRE tactics for {mitre_str}.\n"
            f"* **Action Required:**\n"
            f"  1. **Immediate:** Delete the pod and apply a NetworkPolicy in the "
            f"`{ns}` namespace to block all NodePort exposure.\n"
            f"  2. **Follow-up:** Review pod logs for external connections and audit "
            f"the RBAC permissions that allowed `{principal}` to launch a privileged "
            f"pod without a controller."
        )

    if "OFF_HOURS_ASSUME_ROLE" in signals:
        return (
            f"* **When:** {time_str}\n"
            f"* **Where/Who:** `{ns}` region, via the `{principal}` function\n"
            f"* **What Happened:** A high-privilege IAM role was assumed in the "
            f"early hours of the morning and used to access sensitive (PII) resources, "
            f"with a short 15-minute session TTL typical of automated scripts.\n"
            f"* **The Threat:** This is consistent with a compromised Lambda function "
            f"or stolen IAM token being used to exfiltrate data outside working hours. "
            f"(Risk Score: {score}/100). Matches MITRE tactics for {mitre_str}.\n"
            f"* **Action Required:**\n"
            f"  1. **Immediate:** Rotate all credentials for `{principal}` and "
            f"immediately revoke the active IAM session.\n"
            f"  2. **Follow-up:** Add a Service Control Policy (SCP) restricting "
            f"off-hours AssumeRole for this role ARN and enable GuardDuty anomaly "
            f"detection on this account."
        )

    # generic fallback
    return (
        f"* **When:** {time_str}\n"
        f"* **Where/Who:** `{ns}` region/namespace, via the `{principal}` account\n"
        f"* **What Happened:** {count} suspicious event(s) were detected with the "
        f"following risk signals: {', '.join(signals)}.\n"
        f"* **The Threat:** Anomalous ephemeral resource activity was detected that "
        f"deviates from the established baseline for this principal. "
        f"(Risk Score: {score}/100). Matches MITRE tactics for {mitre_str}.\n"
        f"* **Action Required:**\n"
        f"  1. **Immediate:** Review and contain all active sessions for `{principal}`.\n"
        f"  2. **Follow-up:** Apply least-privilege remediation and investigate the "
        f"full event trail for this incident."
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
