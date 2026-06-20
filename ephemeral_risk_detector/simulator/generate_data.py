"""
simulator/generate_data.py   [Foundation — shared by all options]
=================================================================
Generates three synthetic event log CSVs and a ground truth label file.
No real cloud infrastructure is needed.

Output files (written to data/):
    cloud_events.csv   — 500 AWS-style audit log events
    k8s_events.csv     — 500 Kubernetes pod/service/RBAC events
    iam_sessions.csv   — 200 IAM AssumeRole session events
    ground_truth.csv   — is_risky, anomaly_type, severity per event_id

Anomaly distribution injected:
    MINING_BURST          CRITICAL   ~6 %   (crypto-mining RunInstances)
    PUBLIC_EXPOSURE       HIGH       ~4 %   (debug pod with public IP)
    PRIVILEGED_NO_CTRL    HIGH       ~2 %   (privileged pod, no owner)
    OFF_HOURS_ASSUME_ROLE MEDIUM     ~6 %   (IAM session at 3 AM)
    Legitimate HPA bursts NONE       ~44%   (noise — must NOT be flagged)
    Normal lifecycle      NONE       ~38%
"""

import os
import random
import pandas as pd
from datetime import datetime, timedelta
from faker import Faker

fake   = Faker()
random.seed(42)
Faker.seed(42)

# ── constants ────────────────────────────────────────────────────────────────

BASE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data")

# 7-day simulation window
SIM_START = datetime(2026, 6, 12, 0, 0, 0)
SIM_END   = datetime(2026, 6, 19, 0, 0, 0)

# Principals
SVC_ACCOUNTS = [
    "svc-cicd-pipeline",   # will be 'compromised' in mining burst
    "svc-etl-batch",
    "svc-monitoring",
    "svc-backup",
    "svc-logging",
    "svc-autoscaler",
]
USERS = ["dev-jsmith", "dev-arao", "ops-mlee", "admin-pkumar", "dev-sgupta"]
LAMBDA_FNS = ["lambda-prod-fn", "lambda-report-fn", "lambda-notify-fn"]

ALL_PRINCIPALS = SVC_ACCOUNTS + USERS + LAMBDA_FNS

# K8s namespaces
NAMESPACES = ["production", "staging", "ci-jobs", "monitoring", "default"]

# AWS regions
REGIONS = ["us-east-1", "us-west-2", "eu-west-1"]

# High-CPU (mining-friendly) instance types
MINING_INSTANCES = ["c5.4xlarge", "c5.9xlarge", "c4.8xlarge", "g4dn.xlarge"]
NORMAL_INSTANCES = ["t3.medium", "t3.large", "m5.large", "r5.xlarge", "t3.micro"]

# High-privilege IAM roles
HIGH_PRIV_ROLES = [
    "arn:aws:iam::123456:role/Prod-S3-FullAccess",
    "arn:aws:iam::123456:role/EC2-Admin-Role",
    "arn:aws:iam::123456:role/RDS-FullAccess",
]
NORMAL_ROLES = [
    "arn:aws:iam::123456:role/EC2-AutoScale-Role",
    "arn:aws:iam::123456:role/CI-Build-Role",
    "arn:aws:iam::123456:role/Lambda-ReadOnly-Role",
    "arn:aws:iam::123456:role/S3-ReadOnly-Role",
]

# Cloud event action types
CLOUD_ACTIONS = [
    "RunInstances", "TerminateInstances", "DescribeInstances",
    "CreateBucket", "PutObject", "GetObject", "DeleteObject",
    "CreateSnapshot", "AttachVolume", "CreateKeyPair",
    "CreateSecurityGroup", "AuthorizeSecurityGroupIngress",
    "StartInstances", "StopInstances",
]

# K8s event action types
K8S_ACTIONS = [
    "pod.create", "pod.delete", "pod.update",
    "service.create", "service.delete",
    "deployment.scale", "rbac.rolebinding.create",
    "pod.exec", "configmap.create",
]


# ── helpers ──────────────────────────────────────────────────────────────────

def rand_ts(start: datetime, end: datetime) -> datetime:
    delta = int((end - start).total_seconds())
    return start + timedelta(seconds=random.randint(0, delta))


def ts_at(day_offset: int, hour: int, minute: int) -> datetime:
    """Return a specific timestamp within the simulation window."""
    return SIM_START + timedelta(days=day_offset, hours=hour, minutes=minute)


def make_resource_id(prefix: str) -> str:
    return f"{prefix}-{fake.lexify('????').lower()}-{random.randint(1000,9999)}"


# ── cloud events ─────────────────────────────────────────────────────────────

def _normal_cloud_event(event_id: str, ts: datetime) -> dict:
    principal = random.choice(ALL_PRINCIPALS)
    action    = random.choice(CLOUD_ACTIONS)
    return {
        "event_id"          : event_id,
        "timestamp"         : ts.isoformat(),
        "source"            : "cloud",
        "event_type"        : action,
        "principal"         : principal,
        "namespace_or_region": random.choice(REGIONS),
        "resource_id"       : make_resource_id("i"),
        "resource_type"     : "ec2-instance",
        "ttl_minutes"       : round(random.uniform(30, 480), 1),
        "public_ip"         : None,
        "privileged"        : False,
        "controller_owner"  : "AutoScaling" if "Scale" in action else None,
        "tags_present"      : random.random() > 0.15,
        "hour_of_day"       : ts.hour,
        "instance_type"     : random.choice(NORMAL_INSTANCES),
        "sensitive_resource": False,
        "burst_group_id"    : None,
        "is_risky"          : False,
        "anomaly_type"      : "NORMAL",
        "severity"          : "NONE",
    }


def _mining_burst_events(start_event_num: int, burst_ts: datetime,
                         burst_size: int, burst_id: str) -> list:
    """
    Anomaly — CRITICAL
    Simulates a compromised CI/CD service account spinning up many
    high-CPU instances in a short window at an unusual hour (3–4 AM).
    Maps to MITRE ATT&CK T1496: Resource Hijacking.
    """
    events = []
    for i in range(burst_size):
        ts  = burst_ts + timedelta(seconds=i * 12)   # one every ~12 s
        eid = f"CLD-{start_event_num + i:05d}"
        events.append({
            "event_id"          : eid,
            "timestamp"         : ts.isoformat(),
            "source"            : "cloud",
            "event_type"        : "RunInstances",
            "principal"         : "svc-cicd-pipeline",   # compromised account
            "namespace_or_region": "us-east-1",
            "resource_id"       : make_resource_id("i"),
            "resource_type"     : "spot-instance",
            "ttl_minutes"       : round(random.uniform(80, 100), 1),
            "public_ip"         : None,
            "privileged"        : False,
            "controller_owner"  : None,               # no legit owner
            "tags_present"      : False,              # no tags — suspicious
            "hour_of_day"       : ts.hour,
            "instance_type"     : random.choice(MINING_INSTANCES),
            "sensitive_resource": False,
            "burst_group_id"    : burst_id,
            "is_risky"          : True,
            "anomaly_type"      : "MINING_BURST",
            "severity"          : "CRITICAL",
        })
    return events


def generate_cloud_events(n_normal: int = 460) -> pd.DataFrame:
    rows   = []
    ctr    = 1

    # ── inject anomaly: mining burst 1 — June 15 at 03:14 AM ──
    burst1_ts = ts_at(day_offset=3, hour=3, minute=14)
    rows.extend(_mining_burst_events(ctr, burst1_ts, burst_size=20,
                                     burst_id="BURST-C-001"))
    ctr += 20

    # ── inject anomaly: mining burst 2 — June 17 at 04:02 AM ──
    burst2_ts = ts_at(day_offset=5, hour=4, minute=2)
    rows.extend(_mining_burst_events(ctr, burst2_ts, burst_size=15,
                                     burst_id="BURST-C-002"))
    ctr += 15

    # ── normal cloud events ──
    for _ in range(n_normal):
        ts = rand_ts(SIM_START, SIM_END)
        rows.append(_normal_cloud_event(f"CLD-{ctr:05d}", ts))
        ctr += 1

    df = pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)
    return df


# ── K8s events ───────────────────────────────────────────────────────────────

def _debug_pod_event(event_id: str, ts: datetime) -> dict:
    """
    Anomaly — HIGH
    Developer launches a privileged debug pod with a public IP and no
    controller owner for 'quick testing'.
    Maps to MITRE ATT&CK T1190: Exploit Public-Facing Application.
    """
    return {
        "event_id"          : event_id,
        "timestamp"         : ts.isoformat(),
        "source"            : "k8s",
        "event_type"        : "pod.create",
        "principal"         : "dev-jsmith",
        "namespace_or_region": "staging",
        "resource_id"       : make_resource_id("pod"),
        "resource_type"     : "debug-pod",
        "ttl_minutes"       : 11.0,
        "public_ip"         : "203.0.113.42",    # exposed to internet
        "privileged"        : True,
        "controller_owner"  : None,              # no Deployment/Job owner
        "tags_present"      : False,
        "hour_of_day"       : ts.hour,
        "instance_type"     : None,
        "sensitive_resource": False,
        "burst_group_id"    : None,
        "is_risky"          : True,
        "anomaly_type"      : "PUBLIC_EXPOSURE",
        "severity"          : "HIGH",
    }


def _privileged_pod_event(event_id: str, ts: datetime) -> dict:
    """
    Anomaly — HIGH
    Privileged pod with no controller owner — potential container escape risk.
    """
    return {
        "event_id"          : event_id,
        "timestamp"         : ts.isoformat(),
        "source"            : "k8s",
        "event_type"        : "pod.create",
        "principal"         : "dev-arao",
        "namespace_or_region": "default",
        "resource_id"       : make_resource_id("pod"),
        "resource_type"     : "privileged-pod",
        "ttl_minutes"       : round(random.uniform(5, 20), 1),
        "public_ip"         : None,
        "privileged"        : True,
        "controller_owner"  : None,
        "tags_present"      : False,
        "hour_of_day"       : ts.hour,
        "instance_type"     : None,
        "sensitive_resource": False,
        "burst_group_id"    : None,
        "is_risky"          : True,
        "anomaly_type"      : "PRIVILEGED_NO_CTRL",
        "severity"          : "HIGH",
    }


def _hpa_autoscale_burst(start_event_num: int, burst_ts: datetime,
                          burst_size: int, burst_id: str,
                          namespace: str = "production") -> list:
    """
    Legitimate noise — NONE (must NOT be flagged as risky)
    HPA autoscaler responding to a traffic spike. Looks like a burst
    but has controller_owner=HPA and proper tags — should score 0.
    This is the false-positive trap from PS3 Case 4.
    """
    events = []
    for i in range(burst_size):
        ts  = burst_ts + timedelta(seconds=i * 3)
        eid = f"K8S-{start_event_num + i:05d}"
        events.append({
            "event_id"          : eid,
            "timestamp"         : ts.isoformat(),
            "source"            : "k8s",
            "event_type"        : "pod.create",
            "principal"         : "svc-autoscaler",
            "namespace_or_region": namespace,
            "resource_id"       : make_resource_id("pod"),
            "resource_type"     : "job-pod",
            "ttl_minutes"       : round(random.uniform(10, 30), 1),
            "public_ip"         : None,
            "privileged"        : False,
            "controller_owner"  : "HPA",         # key: legit controller
            "tags_present"      : True,           # key: properly tagged
            "hour_of_day"       : ts.hour,
            "instance_type"     : None,
            "sensitive_resource": False,
            "burst_group_id"    : burst_id,
            "is_risky"          : False,          # ground truth: NOT risky
            "anomaly_type"      : "NORMAL",
            "severity"          : "NONE",
        })
    return events


def _normal_k8s_event(event_id: str, ts: datetime) -> dict:
    principal = random.choice(SVC_ACCOUNTS + USERS)
    action    = random.choice(K8S_ACTIONS)
    ns        = random.choice(NAMESPACES)
    return {
        "event_id"          : event_id,
        "timestamp"         : ts.isoformat(),
        "source"            : "k8s",
        "event_type"        : action,
        "principal"         : principal,
        "namespace_or_region": ns,
        "resource_id"       : make_resource_id("pod"),
        "resource_type"     : "job-pod",
        "ttl_minutes"       : round(random.uniform(5, 120), 1),
        "public_ip"         : None,
        "privileged"        : False,
        "controller_owner"  : random.choice(["Deployment", "Job", "CronJob", None]),
        "tags_present"      : random.random() > 0.2,
        "hour_of_day"       : ts.hour,
        "instance_type"     : None,
        "sensitive_resource": False,
        "burst_group_id"    : None,
        "is_risky"          : False,
        "anomaly_type"      : "NORMAL",
        "severity"          : "NONE",
    }


def generate_k8s_events(n_normal: int = 405) -> pd.DataFrame:
    rows = []
    ctr  = 1

    # ── inject anomaly: debug pod with public IP — June 14 at 14:22 ──
    rows.append(_debug_pod_event(f"K8S-{ctr:05d}",
                                 ts_at(day_offset=2, hour=14, minute=22)))
    ctr += 1

    # ── inject anomaly: privileged pod no controller — June 16 at 10:30 ──
    rows.append(_privileged_pod_event(f"K8S-{ctr:05d}",
                                      ts_at(day_offset=4, hour=10, minute=30)))
    ctr += 1

    # ── inject noise: HPA morning autoscale — June 14 at 09:15 ──
    burst1 = _hpa_autoscale_burst(ctr,
                                   ts_at(day_offset=2, hour=9, minute=15),
                                   burst_size=40, burst_id="BURST-K-001")
    rows.extend(burst1)
    ctr += 40

    # ── inject noise: HPA evening spike — June 15 at 18:30 ──
    burst2 = _hpa_autoscale_burst(ctr,
                                   ts_at(day_offset=3, hour=18, minute=30),
                                   burst_size=30, burst_id="BURST-K-002",
                                   namespace="production")
    rows.extend(burst2)
    ctr += 30

    # ── inject noise: CI/CD job pods (business hours, properly tagged) ──
    for day in range(5):   # Mon–Fri
        for run in range(3):
            ci_ts = ts_at(day_offset=day, hour=random.randint(9, 17),
                          minute=random.randint(0, 59))
            for j in range(8):
                ts  = ci_ts + timedelta(seconds=j * 20)
                eid = f"K8S-{ctr:05d}"
                rows.append({
                    "event_id"          : eid,
                    "timestamp"         : ts.isoformat(),
                    "source"            : "k8s",
                    "event_type"        : "pod.create",
                    "principal"         : "svc-cicd-pipeline",
                    "namespace_or_region": "ci-jobs",
                    "resource_id"       : make_resource_id("pod"),
                    "resource_type"     : "ci-runner",
                    "ttl_minutes"       : round(random.uniform(3, 15), 1),
                    "public_ip"         : None,
                    "privileged"        : False,
                    "controller_owner"  : "Job",     # legit Job controller
                    "tags_present"      : True,
                    "hour_of_day"       : ts.hour,
                    "instance_type"     : None,
                    "sensitive_resource": False,
                    "burst_group_id"    : f"CI-RUN-{day}-{run}",
                    "is_risky"          : False,
                    "anomaly_type"      : "NORMAL",
                    "severity"          : "NONE",
                })
                ctr += 1

    # ── normal K8s events ──
    for _ in range(n_normal):
        ts = rand_ts(SIM_START, SIM_END)
        rows.append(_normal_k8s_event(f"K8S-{ctr:05d}", ts))
        ctr += 1

    df = pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)
    return df


# ── IAM sessions ─────────────────────────────────────────────────────────────

def _off_hours_assume_role(event_id: str, ts: datetime,
                            anomaly_type: str = "OFF_HOURS_ASSUME_ROLE") -> dict:
    """
    Anomaly — MEDIUM
    High-privilege role assumed outside business hours and used to access
    a sensitive (PII) resource.
    Maps to MITRE ATT&CK T1078: Valid Accounts.
    """
    return {
        "event_id"          : event_id,
        "timestamp"         : ts.isoformat(),
        "source"            : "iam",
        "event_type"        : "AssumeRole",
        "principal"         : "lambda-prod-fn",
        "namespace_or_region": "us-east-1",
        "resource_id"       : random.choice(HIGH_PRIV_ROLES),
        "resource_type"     : "iam-session",
        "ttl_minutes"       : 15.0,
        "public_ip"         : None,
        "privileged"        : True,
        "controller_owner"  : None,
        "tags_present"      : False,
        "hour_of_day"       : ts.hour,
        "instance_type"     : None,
        "sensitive_resource": True,      # accessed PII S3 bucket
        "burst_group_id"    : None,
        "is_risky"          : True,
        "anomaly_type"      : anomaly_type,
        "severity"          : "MEDIUM",
    }


def _normal_iam_event(event_id: str, ts: datetime) -> dict:
    principal = random.choice(ALL_PRINCIPALS)
    role      = random.choice(NORMAL_ROLES)
    hour      = ts.hour
    return {
        "event_id"          : event_id,
        "timestamp"         : ts.isoformat(),
        "source"            : "iam",
        "event_type"        : random.choice(["AssumeRole", "GetSessionToken",
                                             "CreateAccessKey", "ListRoles"]),
        "principal"         : principal,
        "namespace_or_region": random.choice(REGIONS),
        "resource_id"       : role,
        "resource_type"     : "iam-session",
        "ttl_minutes"       : round(random.uniform(15, 60), 1),
        "public_ip"         : None,
        "privileged"        : False,
        "controller_owner"  : None,
        "tags_present"      : random.random() > 0.3,
        "hour_of_day"       : hour,
        "instance_type"     : None,
        "sensitive_resource": False,
        "burst_group_id"    : None,
        "is_risky"          : False,
        "anomaly_type"      : "NORMAL",
        "severity"          : "NONE",
    }


def generate_iam_events(n_normal: int = 188) -> pd.DataFrame:
    rows = []
    ctr  = 1

    # ── inject anomaly: off-hours role session 1 — June 13 at 02:05 ──
    rows.append(_off_hours_assume_role(
        f"IAM-{ctr:05d}", ts_at(day_offset=1, hour=2, minute=5)))
    ctr += 1

    # ── inject anomaly: off-hours role session 2 — June 16 at 03:40 ──
    rows.append(_off_hours_assume_role(
        f"IAM-{ctr:05d}", ts_at(day_offset=4, hour=3, minute=40)))
    ctr += 1

    # ── inject anomaly: off-hours role session 3 — June 18 at 01:22 ──
    rows.append(_off_hours_assume_role(
        f"IAM-{ctr:05d}", ts_at(day_offset=6, hour=1, minute=22)))
    ctr += 1

    # ── inject anomaly: off-hours role session 4 — June 17 at 04:10 ──
    # (close to the cloud mining burst on same day — correlator will link them)
    rows.append(_off_hours_assume_role(
        f"IAM-{ctr:05d}", ts_at(day_offset=5, hour=4, minute=10),
        anomaly_type="OFF_HOURS_ASSUME_ROLE"))
    ctr += 1

    # ── normal IAM events ──
    for _ in range(n_normal):
        ts = rand_ts(SIM_START, SIM_END)
        rows.append(_normal_iam_event(f"IAM-{ctr:05d}", ts))
        ctr += 1

    df = pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)
    return df


# ── ground truth ─────────────────────────────────────────────────────────────

def build_ground_truth(*dfs: pd.DataFrame) -> pd.DataFrame:
    """
    Merge all event DataFrames and extract ground truth labels.
    Used by evaluator.py to compute precision / recall.
    """
    combined = pd.concat(dfs, ignore_index=True)
    gt = combined[["event_id", "is_risky", "anomaly_type", "severity"]].copy()
    return gt


# ── main entry ───────────────────────────────────────────────────────────────

def generate_all():
    os.makedirs(BASE_DIR, exist_ok=True)

    print("  Generating cloud audit log events ...")
    cloud_df = generate_cloud_events()
    cloud_df.to_csv(os.path.join(BASE_DIR, "cloud_events.csv"), index=False)
    print(f"  → cloud_events.csv   : {len(cloud_df):>4} rows  "
          f"(risky: {cloud_df['is_risky'].sum()})")

    print("  Generating Kubernetes events ...")
    k8s_df = generate_k8s_events()
    k8s_df.to_csv(os.path.join(BASE_DIR, "k8s_events.csv"), index=False)
    print(f"  → k8s_events.csv     : {len(k8s_df):>4} rows  "
          f"(risky: {k8s_df['is_risky'].sum()})")

    print("  Generating IAM session events ...")
    iam_df = generate_iam_events()
    iam_df.to_csv(os.path.join(BASE_DIR, "iam_sessions.csv"), index=False)
    print(f"  → iam_sessions.csv   : {len(iam_df):>4} rows  "
          f"(risky: {iam_df['is_risky'].sum()})")

    print("  Building ground truth labels ...")
    gt_df = build_ground_truth(cloud_df, k8s_df, iam_df)
    gt_df.to_csv(os.path.join(BASE_DIR, "ground_truth.csv"), index=False)

    total  = len(gt_df)
    risky  = gt_df["is_risky"].sum()
    print(f"  → ground_truth.csv   : {total:>4} rows  "
          f"(risky: {risky} = {risky/total*100:.1f}%)")

    print("\n  Anomaly breakdown:")
    breakdown = gt_df[gt_df["is_risky"]]["anomaly_type"].value_counts()
    for atype, count in breakdown.items():
        print(f"    {atype:<30} {count}")


if __name__ == "__main__":
    generate_all()
