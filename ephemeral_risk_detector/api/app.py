"""
api/app.py  [Foundation]
=========================
FastAPI backend.
- Runs the full pipeline on startup (classify → score → correlate → evaluate)
- Caches all results in memory
- Serves REST endpoints consumed by the React frontend on port 5173
- CORS is enabled so the Vite dev server can call these endpoints freely

Endpoints
---------
GET /api/stats              → KPI summary counts for dashboard cards
GET /api/events             → paginated scored events list
GET /api/incidents          → correlated incidents with narratives
GET /api/burst-timeline     → per-minute time series (React-ready format)
GET /api/ttl-dist           → TTL histogram bins + counts
GET /api/risk-by-principal  → top-N principals by cumulative risk score
GET /api/evaluate           → full evaluation metrics (precision/recall/etc.)
"""
from dotenv import load_dotenv
load_dotenv()
import os
import sys
import pandas as pd

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from engine.classifier import classify
from engine.risk_scorer import score
from engine.correlator  import correlate
from engine.evaluator   import evaluate

DATA_DIR  = os.path.join(BASE_DIR, "data")
USE_LLM   = bool(os.getenv("GROQ_API_KEY", ""))

_cache: dict = {}


# ── pipeline ──────────────────────────────────────────────────────────────────

def _run_pipeline():
    print("\n[API] Starting pipeline ...")

    cloud = pd.read_csv(os.path.join(DATA_DIR, "cloud_events.csv"))
    k8s   = pd.read_csv(os.path.join(DATA_DIR, "k8s_events.csv"))
    iam   = pd.read_csv(os.path.join(DATA_DIR, "iam_sessions.csv"))
    df    = pd.concat([cloud, k8s, iam], ignore_index=True)
    print(f"[API]  Loaded {len(df)} events.")

    df = classify(df)
    print("[API]  Phase 3 — Classifier done.")

    df = score(df)
    print("[API]  Phase 4 — Scorer done.")

    raw_alert_count = int((df["risk_score"] > 20).sum())
    incidents = correlate(df, use_llm=USE_LLM)
    print(f"[API]  Phase 5 — {len(incidents)} incidents"
          f"{' (with LLM narratives)' if USE_LLM else ' (template narratives)'}.")

    metrics = evaluate(df, incidents, raw_alert_count)
    print(f"[API]  Phase 6 — P={metrics['precision']:.0%}  "
          f"R={metrics['recall']:.0%}  "
          f"AlertReduction={metrics['alert_reduction_pct']}%")

    _cache["df"]        = df
    _cache["incidents"] = incidents
    _cache["metrics"]   = metrics
    _cache["raw_count"] = raw_alert_count
    print("[API] Pipeline done. React frontend: http://localhost:5173\n")


@asynccontextmanager
async def lifespan(app: FastAPI):
    _run_pipeline()
    yield


app = FastAPI(
    title="Ephemeral Risk Detector API",
    version="1.0.0",
    lifespan=lifespan,
)

# Allow Vite dev server (5173) and any production build origin
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "*"],
    allow_methods=["GET"],
    allow_headers=["*"],
)


# ── /api/stats ────────────────────────────────────────────────────────────────

@app.get("/api/stats")
async def get_stats():
    df        = _cache["df"]
    incidents = _cache["incidents"]
    metrics   = _cache["metrics"]
    sev_dist  = df["severity_label"].value_counts().to_dict()
    return {
        "total_events"          : int(len(df)),
        "ephemeral_count"       : int(df["is_ephemeral"].sum()),
        "persistent_count"      : int((~df["is_ephemeral"]).sum()),
        "total_incidents"       : len(incidents),
        "critical_incidents"    : sum(1 for i in incidents if i["severity"] == "CRITICAL"),
        "high_incidents"        : sum(1 for i in incidents if i["severity"] == "HIGH"),
        "medium_incidents"      : sum(1 for i in incidents if i["severity"] == "MEDIUM"),
        "raw_alerts"            : _cache["raw_count"],
        "alert_reduction_pct"   : metrics["alert_reduction_pct"],
        "noise_suppression_pct" : metrics["noise_suppression_pct"],
        "severity_distribution" : sev_dist,
    }


# ── /api/events ───────────────────────────────────────────────────────────────

@app.get("/api/events")
async def get_events(
    page:      int = Query(1, ge=1),
    page_size: int = Query(50, ge=10, le=200),
    severity:  str = Query("ALL"),
    source:    str = Query("ALL"),
):
    df = _cache["df"].copy()
    if severity != "ALL":
        df = df[df["severity_label"] == severity]
    if source != "ALL":
        df = df[df["source"] == source]

    df = df.sort_values("risk_score", ascending=False)
    total = len(df)
    start = (page - 1) * page_size

    cols = [
        "event_id", "timestamp", "source", "event_type", "principal",
        "namespace_or_region", "resource_type", "ttl_minutes",
        "is_ephemeral", "ephemeral_type", "risk_score", "severity_label",
        "triggered_signals", "hour_of_day", "tags_present",
        "public_ip", "privileged", "controller_owner",
    ]
    cols = [c for c in cols if c in df.columns]
    rows = df[cols].iloc[start : start + page_size]
    return {
        "total"    : total,
        "page"     : page,
        "page_size": page_size,
        "events"   : rows.fillna("").to_dict(orient="records"),
    }


# ── /api/incidents ────────────────────────────────────────────────────────────

@app.get("/api/incidents")
async def get_incidents(severity: str = Query("ALL")):
    incidents = _cache["incidents"]
    if severity != "ALL":
        incidents = [i for i in incidents if i["severity"] == severity]
    # drop raw event_ids list (can be large); evidence is enough for UI
    return {
        "total"    : len(incidents),
        "incidents": [{k: v for k, v in i.items() if k != "event_ids"}
                      for i in incidents],
    }


# ── /api/burst-timeline ───────────────────────────────────────────────────────

@app.get("/api/burst-timeline")
async def get_burst_timeline():
    """
    Returns a single pre-merged array that Recharts can consume directly.
    Each object: { minute, all_count, risky_count }
    Bucketed at 30-min intervals to keep the chart readable.
    """
    df = _cache["df"].copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["bucket"]    = df["timestamp"].dt.floor("30min").dt.strftime("%m-%d %H:%M")

    all_counts   = df.groupby("bucket").size().rename("all_count")
    risky_counts = (
        df[df["risk_score"] > 0].groupby("bucket").size().rename("risky_count")
    )
    merged = pd.concat([all_counts, risky_counts], axis=1).fillna(0).reset_index()
    merged = merged.rename(columns={"bucket": "minute"})
    merged["all_count"]   = merged["all_count"].astype(int)
    merged["risky_count"] = merged["risky_count"].astype(int)

    return {"data": merged.to_dict(orient="records")}


# ── /api/ttl-dist ─────────────────────────────────────────────────────────────

@app.get("/api/ttl-dist")
async def get_ttl_dist(bins: int = Query(20, ge=5, le=50)):
    """
    Returns histogram bin labels + counts for ephemeral resource TTLs.
    """
    df       = _cache["df"]
    ttl_vals = df[df["is_ephemeral"]]["ttl_minutes"].dropna()

    hist, edges = pd.cut(ttl_vals, bins=bins, retbins=True)
    counts = hist.value_counts(sort=False).values.tolist()
    labels = [f"{edges[i]:.0f}–{edges[i+1]:.0f}" for i in range(len(edges)-1)]

    return {"labels": labels, "counts": counts}


# ── /api/risk-by-principal ────────────────────────────────────────────────────

@app.get("/api/risk-by-principal")
async def get_risk_by_principal(top_n: int = Query(10, ge=1, le=30)):
    df  = _cache["df"]
    top = (
        df[df["risk_score"] > 0]
        .groupby("principal")["risk_score"]
        .sum()
        .sort_values(ascending=False)
        .head(top_n)
        .reset_index()
    )
    return {
        "data": top.rename(
            columns={"principal": "name", "risk_score": "score"}
        ).to_dict(orient="records")
    }


# ── /api/evaluate ─────────────────────────────────────────────────────────────

@app.get("/api/evaluate")
async def get_evaluate():
    m = dict(_cache["metrics"])
    m.pop("classification_report", None)
    return m
