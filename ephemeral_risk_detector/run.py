"""
Ephemeral Cloud & Kubernetes Resource Risk Detector
====================================================
Entry point — generates data (if missing) then starts the FastAPI backend.

Usage
-----
    python run.py           # use existing data/ CSVs (or generate if absent)
    python run.py --regen   # force-regenerate all CSVs

Two terminals are required to run the full application:

  Terminal 1 (Backend):   python run.py
  Terminal 2 (Frontend):  cd frontend && npm install && npm run dev

Then open:  http://localhost:5173

Pipeline order
--------------
  Phase 2 : simulator/generate_data.py  → data/*.csv
  Phase 3 : engine/classifier.py        → is_ephemeral per event
  Phase 4 : engine/risk_scorer.py       → risk_score + severity
  Phase 5a: engine/correlator.py        → time-window incident grouping
  Phase 5b: engine/correlator.py        → Groq LLM narrative per incident
  Phase 6 : engine/evaluator.py         → precision / recall / alert reduction
  Phase 7 : api/app.py                  → FastAPI REST API on port 8000

Optional — enable real LLM narratives (Phase 5b / Option A):
    export GROQ_API_KEY=your_key_here
    python run.py
"""
from dotenv import load_dotenv
load_dotenv()
import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")

REQUIRED = ["cloud_events.csv", "k8s_events.csv",
            "iam_sessions.csv", "ground_truth.csv"]


def data_exists():
    return all(os.path.exists(os.path.join(DATA_DIR, f)) for f in REQUIRED)


def run_simulator():
    print("\n" + "=" * 55)
    print("  PHASE 2 — Data Simulation")
    print("=" * 55)
    from simulator.generate_data import generate_all
    generate_all()
    print("[OK] CSVs written to data/\n")


def start_api():
    print("=" * 55)
    print("  PHASE 7 — FastAPI Backend")
    print("=" * 55)
    print("  API URL : http://localhost:8000")
    print("  Docs    : http://localhost:8000/docs")
    print()
    print("  Open a second terminal and run:")
    print("    cd frontend && npm install && npm run dev")
    print()
    print("  Then visit: http://localhost:5173")
    print()
    if os.getenv("GROQ_API_KEY"):
        print("  GROQ_API_KEY detected — LLM narratives ENABLED (Option A)")
    else:
        print("  No GROQ_API_KEY — using template narratives (set key to enable LLM)")
    print("=" * 55 + "\n")

    import uvicorn
    uvicorn.run("api.app:app", host="0.0.0.0", port=8000, reload=False)


if __name__ == "__main__":
    os.makedirs(DATA_DIR, exist_ok=True)

    if "--regen" in sys.argv or not data_exists():
        run_simulator()
    else:
        print("\n[Phase 2] Pre-generated data found in data/ — skipping simulation.")
        print("          Pass --regen to regenerate.\n")

    start_api()
