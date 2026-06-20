# Ephemeral Cloud & Kubernetes Resource Risk Detector
### Société Générale GRC Hackathon — Problem Statement 3

> **Track:** Cloud Security Governance & Risk  
> **Difficulty:** Intermediate–Advanced  
> **Approach:** Option B (Statistical Core) + Option A (LLM Narrative)

---

## Table of Contents
1. [Problem Summary](#problem-summary)
2. [Solution Architecture](#solution-architecture)
3. [Project Structure](#project-structure)
4. [Prerequisites](#prerequisites)
5. [Setup & Run](#setup--run)
6. [Enabling LLM Narratives (Option A)](#enabling-llm-narratives-option-a)
7. [API Reference](#api-reference)
8. [Data Dictionary](#data-dictionary)
9. [Detection Logic](#detection-logic)
10. [Evaluation Results](#evaluation-results)
11. [Sample Incidents](#sample-incidents)
12. [Framework Alignment](#framework-alignment)

---

## Problem Summary

Traditional security controls (quarterly scans, daily inventory syncs) were never designed for ephemeral cloud resources — pods, spot instances, and IAM sessions that live for minutes and disappear. This leaves a critical blind spot:

- A compromised CI/CD account spun up 20 mining VMs at 3 AM → all terminated before the SOC shift
- A debug pod with a public IP ran for 11 minutes → found and exploited by an external scanner
- A high-privilege AssumeRole session fired at 2 AM → never correlated to the Lambda that triggered it
- 40 autoscale pods generated 40 individual alerts → buried a real credential-abuse alert

**This system detects all four scenarios, suppresses the autoscale noise, and reduces 41 raw alerts to 9 incidents.**

---

## Solution Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        DATA SIMULATION                          │
│   Cloud Audit Logs (500)  K8s Events (500)  IAM Sessions (200) │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                    ┌───────────▼───────────┐
                    │  Phase 3: CLASSIFIER  │  Option B
                    │  Ephemeral vs         │  Heuristic rules:
                    │  Persistent tagging   │  TTL / controller /
                    └───────────┬───────────┘  labels / type
                                │
                    ┌───────────▼───────────┐
                    │  Phase 4: RISK SCORER │  Option B
                    │  Z-score baselines    │  6 signals weighted
                    │  per principal        │  Legit autoscale → 0
                    └───────────┬───────────┘
                                │
                    ┌───────────▼───────────┐
                    │  Phase 5a: CORRELATOR │  Option B
                    │  10-min bucket        │  41 alerts → 9 incidents
                    │  time-window grouping │  78% alert reduction
                    └───────────┬───────────┘
                                │
                    ┌───────────▼───────────┐
                    │  Phase 5b: LLM NARR.  │  Option A  ← Groq API
                    │  Per-incident analyst │  1 call per incident
                    │  narrative + MITRE    │  fallback template
                    └───────────┬───────────┘
                                │
                    ┌───────────▼───────────┐
                    │  Phase 6: EVALUATOR   │  Option B
                    │  Precision / Recall   │  vs ground_truth.csv
                    │  F1 / Alert reduction │
                    └───────────┬───────────┘
                                │
              ┌─────────────────┴──────────────────┐
              │                                    │
  ┌───────────▼───────────┐          ┌─────────────▼───────────┐
  │  Phase 7: FastAPI     │          │  Phase 8: React          │
  │  REST API  :8000      │◄────────►│  Dashboard  :5173        │
  │  CORS enabled         │          │  Recharts + Vite         │
  └───────────────────────┘          └─────────────────────────┘
```

---

## Project Structure

```
ephemeral_risk_detector/
│
├── README.md                   ← This file
├── requirements.txt            ← Python dependencies
├── run.py                      ← Entry point (Terminal 1)
├── .env.example                ← Copy to .env for Groq key
│
├── simulator/                  ← Phase 2: Data generation
│   ├── __init__.py
│   └── generate_data.py        ← Generates all 4 CSVs with injected anomalies
│
├── engine/                     ← Detection pipeline
│   ├── __init__.py
│   ├── classifier.py           ← Phase 3 [Option B] Ephemeral classifier
│   ├── risk_scorer.py          ← Phase 4 [Option B] Z-score risk scoring
│   ├── correlator.py           ← Phase 5a [Option B] + 5b [Option A]
│   └── evaluator.py            ← Phase 6 [Option B] Precision/recall metrics
│
├── api/                        ← Phase 7: FastAPI backend
│   ├── __init__.py
│   └── app.py                  ← REST endpoints + CORS + pipeline startup
│
├── data/                       ← Pre-generated CSV files (ready to use)
│   ├── cloud_events.csv        ← 495 AWS-style audit log events
│   ├── k8s_events.csv          ← 597 Kubernetes pod/service events
│   ├── iam_sessions.csv        ← 192 IAM AssumeRole session events
│   └── ground_truth.csv        ← 1,284 labelled rows (is_risky + anomaly_type)
│
└── frontend/                   ← Phase 8: React dashboard
    ├── package.json            ← npm dependencies (React 18, Recharts, Vite)
    ├── vite.config.js          ← Vite config with /api proxy to :8000
    ├── index.html              ← HTML entry point
    └── src/
        ├── main.jsx            ← React root
        ├── App.jsx             ← Root component, API fetching
        ├── App.css             ← Global dark theme CSS
        └── components/
            ├── SummaryCards.jsx    ← 6 KPI cards [Option B]
            ├── EvalMetrics.jsx     ← Precision/recall panel [Option B]
            ├── BurstTimeline.jsx   ← Events/min chart (ComposedChart) [Option B]
            ├── TTLHistogram.jsx    ← Resource lifetime histogram [Option B]
            ├── RiskByPrincipal.jsx ← Top-10 principals bar chart [Option B]
            ├── SeverityPie.jsx     ← Severity distribution donut [Option B]
            └── IncidentTable.jsx   ← Incident queue + narrative panel [B + A]
```

---

## Prerequisites

| Tool | Version | Check |
|---|---|---|
| Python | 3.10 or later | `python --version` |
| pip | bundled with Python | `pip --version` |
| Node.js | 18 or later | `node --version` |
| npm | bundled with Node | `npm --version` |

---

## Setup & Run

### Step 1 — Extract the project

```bash
unzip ephemeral_risk_detector.zip
cd ephemeral_risk_detector
```

### Step 2 — Create and activate a Python virtual environment

**macOS / Linux:**
```bash
python -m venv venv
source venv/bin/activate
```

**Windows (Command Prompt):**
```cmd
python -m venv venv
venv\Scripts\activate.bat
```

**Windows (PowerShell):**
```powershell
python -m venv venv
venv\Scripts\Activate.ps1
```

> Your terminal prompt should now show `(venv)` at the start.

### Step 3 — Install Python dependencies

```bash
pip install -r requirements.txt
```

This installs: `fastapi`, `uvicorn`, `pandas`, `numpy`, `scipy`,
`scikit-learn`, `faker`, `groq`, and `python-multipart`.

### Step 4 — Start the FastAPI backend (Terminal 1)

```bash
python run.py
```

Expected output:
```
[Phase 2] Pre-generated data found in data/ — skipping simulation.

=======================================================
  PHASE 7 — FastAPI Backend
=======================================================
  API URL : http://localhost:8000
  Docs    : http://localhost:8000/docs
  ...
[API] Loaded 1284 events.
[API]  Phase 3 — Classifier done.
[API]  Phase 4 — Scorer done.
[API]  Phase 5 — 9 incidents (template narratives).
[API]  Phase 6 — P=100%  R=100%  AlertReduction=78.0%
[API] Pipeline done. React frontend: http://localhost:5173
```

> Keep this terminal open. The API server runs on **port 8000**.

### Step 5 — Install and start the React frontend (Terminal 2)

Open a new terminal, navigate to the project folder, then:

```bash
cd frontend
npm install
npm run dev
```

Expected output:
```
  VITE v5.x.x  ready in XXX ms

  ➜  Local:   http://localhost:5173/
  ➜  Network: use --host to expose
```

### Step 6 — Open the dashboard

Open your browser and go to:

```
http://localhost:5173
```

You should see the full dashboard with:
- 6 KPI summary cards (events, incidents, alert reduction)
- 6 evaluation metric cards (precision, recall, F1, etc.)
- Burst timeline chart
- TTL distribution histogram
- Risk by principal bar chart
- Severity distribution donut chart
- Incident queue table — **click any row** to expand the LLM narrative

---

## Enabling LLM Narratives (Option A)

By default the system uses rule-based template narratives. To enable
real AI-generated narratives via Groq (free tier, no credit card needed):

**1. Get a free Groq API key:**  
   Visit https://console.groq.com → sign up → API Keys → Create key

**2. Set the key before starting the backend:**

macOS / Linux:
```bash
export GROQ_API_KEY=gsk_your_key_here
python run.py
```

Windows (Command Prompt):
```cmd
set GROQ_API_KEY=gsk_your_key_here
python run.py
```

Windows (PowerShell):
```powershell
$env:GROQ_API_KEY="gsk_your_key_here"
python run.py
```

The startup log will confirm:
```
GROQ_API_KEY detected — LLM narratives ENABLED (Option A)
```

Each incident will now have a GPT-generated analyst report with MITRE
ATT&CK mapping and specific remediation steps.

---

## To Regenerate Data

The data/ folder already contains pre-generated CSVs. To regenerate fresh data:

```bash
python run.py --regen
```

---

## API Reference

All endpoints are served at `http://localhost:8000`.
Interactive docs: `http://localhost:8000/docs`

| Endpoint | Method | Description |
|---|---|---|
| `/api/stats` | GET | KPI summary (events, incidents, alert reduction) |
| `/api/events` | GET | Paginated scored events (`?page=1&severity=HIGH`) |
| `/api/incidents` | GET | Correlated incidents with narratives |
| `/api/burst-timeline` | GET | Events-per-30min time series |
| `/api/ttl-dist` | GET | Ephemeral resource TTL histogram |
| `/api/risk-by-principal` | GET | Top-N principals by risk score |
| `/api/evaluate` | GET | Precision, recall, F1, alert reduction |

---

## Data Dictionary

### cloud_events.csv / k8s_events.csv / iam_sessions.csv

| Column | Type | Description |
|---|---|---|
| `event_id` | string | Unique ID (`CLD-00001`, `K8S-00001`, `IAM-00001`) |
| `timestamp` | ISO datetime | When the event occurred |
| `source` | string | `cloud` / `k8s` / `iam` |
| `event_type` | string | `RunInstances`, `pod.create`, `AssumeRole`, etc. |
| `principal` | string | Identity that triggered the event |
| `namespace_or_region` | string | K8s namespace or AWS region |
| `resource_id` | string | ID of the created/modified resource |
| `resource_type` | string | `spot-instance`, `job-pod`, `iam-session`, etc. |
| `ttl_minutes` | float | How long the resource lived (minutes) |
| `public_ip` | string / null | Public IP if assigned |
| `privileged` | bool | Whether the pod/session has elevated privileges |
| `controller_owner` | string / null | K8s controller (`HPA`, `Deployment`, `Job`, null) |
| `tags_present` | bool | Whether required resource tags are set |
| `hour_of_day` | int | Hour of event (0–23) |
| `instance_type` | string / null | AWS instance type (cloud events only) |
| `sensitive_resource` | bool | Whether PII/financial resource was accessed |
| `burst_group_id` | string / null | Groups events from the same burst scenario |
| `is_risky` | bool | Ground truth label |
| `anomaly_type` | string | `NORMAL`, `MINING_BURST`, `PUBLIC_EXPOSURE`, etc. |
| `severity` | string | `NONE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |

### ground_truth.csv

| Column | Type | Description |
|---|---|---|
| `event_id` | string | Links to the source CSV |
| `is_risky` | bool | True if this event is anomalous |
| `anomaly_type` | string | Specific anomaly category |
| `severity` | string | Ground truth severity level |

---

## Detection Logic

### Risk Signals (Phase 4 — Option B)

| Signal | Weight | Severity | Condition |
|---|---|---|---|
| `MINING_BURST` | 60 | CRITICAL | >10 RunInstances by same principal in 10-min bucket, off-hours, high-CPU instance, no tags |
| `PUBLIC_IP_NON_LB` | 30 | HIGH | Ephemeral K8s pod with public IP and no managed controller |
| `PRIVILEGED_NO_CONTROLLER` | 25 | HIGH | Privileged pod with no Deployment/Job controller |
| `OFF_HOURS_ASSUME_ROLE` | 22 | MEDIUM | High-privilege IAM role assumed before 7am or after 9pm, sensitive resource accessed |
| `UNTAGGED_BURST` | 15 | MEDIUM | Burst of untagged events from same principal, statistically anomalous |
| `NEW_IP_ACCESS` | 10 | LOW | IAM session from previously unseen IP |

### Key Option B Feature — Z-Score Baselines

The scorer computes a per-principal Z-score on burst counts using 10-minute floor buckets.

- **HPA autoscaler** always creates 40 pods → baseline mean ≈ 40, Z-score ≈ 0 → **not flagged**
- **Attacker** (svc-cicd-pipeline) normally creates 2 events, bursts to 20 → Z-score >> 2 → **flagged**

Same burst size, different outcome — because context matters.

### Legit Autoscale Suppression

If `controller_owner ∈ {HPA, Deployment, Job, ...}` AND `tags_present=True`
AND `business_hours` → `risk_score = 0` regardless of burst size.  
This is why 40 HPA pods produce 0 alerts in this system.

---

## Evaluation Results

| Metric | Target | Achieved |
|---|---|---|
| Precision | > 75% | **100.0%** |
| Recall | > 70% | **100.0%** |
| F1 Score | > 0.72 | **1.000** |
| CRITICAL Recall | ≥ 95% | **100.0%** |
| Alert Reduction | ≥ 40% | **78.0%** (41 alerts → 9 incidents) |
| Noise Suppression | ≥ 90% | **100.0%** |
| False Positives | — | **0** |

---

## Sample Incidents

### INC-0001 — CRITICAL — Crypto Mining Burst

**Principal:** `svc-cicd-pipeline`  
**Time:** 2026-06-15 03:15 (3 AM)  
**Events:** 15 × `RunInstances` (c5.4xlarge, c4.8xlarge, g4dn.xlarge)  
**Signals:** `MINING_BURST`, `UNTAGGED_BURST`  
**MITRE:** T1496 Resource Hijacking, T1578 Modify Cloud Compute Infrastructure

> The CI/CD service account launched 15 high-CPU instances in 3 minutes at 3 AM
> with no resource tags and no legitimate controller. This matches a well-known
> cryptocurrency mining pattern. The account is likely compromised.  
> **Action:** Rotate credentials immediately. Terminate all instances from BURST-C-001.
> Review CloudTrail for lateral movement in the past 24h.

---

### INC-0002 — HIGH — Public Debug Pod

**Principal:** `dev-jsmith`  
**Time:** 2026-06-14 14:22  
**TTL:** 11 minutes  
**Signals:** `PUBLIC_IP_NON_LB`, `PRIVILEGED_NO_CONTROLLER`  
**MITRE:** T1190 Exploit Public-Facing Application, T1611 Escape to Host

> A privileged pod with no controller owner was launched in the `staging` namespace
> with a public IP (203.0.113.42). The pod ran for 11 minutes — sufficient for an
> external scanner to detect and attempt exploitation.  
> **Action:** Apply a NetworkPolicy blocking NodePort exposure in `staging`.
> Audit RBAC permissions for `dev-jsmith`.

---

### INC-0003 — MEDIUM — Off-Hours IAM Session

**Principal:** `lambda-prod-fn`  
**Time:** 2026-06-13 02:05 (2 AM)  
**TTL:** 15 minutes  
**Signals:** `OFF_HOURS_ASSUME_ROLE`  
**MITRE:** T1078 Valid Accounts

> A Lambda function assumed `Prod-S3-FullAccess` at 2 AM and accessed a PII S3 bucket.
> The 15-minute session TTL is consistent with automated credential abuse from a
> compromised Lambda execution environment.  
> **Action:** Rotate the Lambda execution role. Add an SCP restricting AssumeRole
> for this ARN outside business hours.

---

## Framework Alignment

| Standard | Control | How This System Addresses It |
|---|---|---|
| NIST SP 800-53 CM-8 | Asset Inventory | All ephemeral resources discovered and catalogued, including sub-60-min assets |
| NIST SP 800-53 SI-4 | System Monitoring | Continuous detection on every event; near-real-time scoring |
| NIST SP 800-53 IR-4 | Incident Handling | Events correlated into incidents with evidence and remediation |
| MITRE ATT&CK T1496 | Resource Hijacking | MINING_BURST signal targets this technique directly |
| MITRE ATT&CK T1190 | Exploit Public App | PUBLIC_IP_NON_LB signal targets this technique |
| MITRE ATT&CK T1078 | Valid Accounts | OFF_HOURS_ASSUME_ROLE covers credential misuse |
| CIS K8s Benchmark | Pod Security | Privileged pod + no controller flagged as HIGH |
| GDPR Article 32 | Security of Processing | PII-sensitive IAM sessions tracked and alerted |
