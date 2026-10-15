# Zero-Trust Access Control Framework Using Continuous Risk Assessment

An academic cybersecurity research project implementing continuous session-risk evaluation with adaptive Zero-Trust policy enforcement, multi-model machine learning (LightGBM, PyTorch GRU, and Hybrid Stacking), interactive attack simulation, and an immutable audit trail.

---

## 🛡️ Core Highlights

- **Beyond Static Login**: Continuously evaluates active sessions against behavioral drift, burst rates, sensitive resource access patterns, and environmental context.
- **Multi-Model ML Architecture**:
  - **Model A (Rule-Based Baseline)**: Static threshold and heuristic rules.
  - **Model B (LightGBM)**: Tabular gradient-boosted trees trained on 17 engineered session features.
  - **Model C (PyTorch GRU)**: Recurrent neural network capturing temporal inter-event dependencies across 10 sequence feature channels.
  - **Model D (Hybrid Fusion)**: Logistic regression meta-learner with robust ensemble blending and probability calibration.
- **Zero-Trust Policy Engine**:
  - Hysteresis damping to prevent policy flickering/flapping.
  - Adaptive access decisions: `allow`, `allow_limited`, `step_up` (MFA required), `deny`, `revoke`.
  - Non-negotiable RBAC invariant: non-admins cannot access admin resources regardless of risk score.
  - Real-time token version invalidation on session revocation.
- **Interactive Cyber Defense Dashboard**:
  - Live animated SVG risk radar and score gauge.
  - Real-time event stream and decision timeline.
  - Adversarial Attack Simulator with preset scenarios: Credential Stuffing, Privilege Escalation, Traffic Burst (DoS), Untrusted Geo/Device Context, and Benign User Activity.
  - One-click Protected Resource Access probe demonstrating immediate revocation enforcement.
  - Full Audit Vault with JSON evidence inspection.

---

## 📊 Empirical ML Benchmark (Test Set Evaluation)

| Architecture | Paradigm | PR-AUC (Primary) | F1-Score | Recall | Precision | ROC-AUC | Inference Latency |
|--------------|----------|-------------------|----------|--------|-----------|---------|-------------------|
| **Rule Baseline** | Static Heuristics | 0.110 | 0.198 | 0.800 | 0.113 | 0.979 | ~0.001 ms |
| **LightGBM** | Tabular Gradient Boosting | 0.235 | 0.270 | 0.500 | 0.185 | 0.880 | 0.004 ms |
| **PyTorch GRU** | Recurrent Neural Network | **0.433** | 0.235 | **0.800** | 0.138 | 0.973 | 0.108 ms |
| **Hybrid Fusion** | Stacking + Sequential Blend | **Ensemble** | **Adaptive** | **High** | **Calibrated** | **Robust** | < 1.5 ms |

---

## 🚀 Quick Start Guide

### 1. Prerequisites
- Python 3.12+
- Node.js 20+
- PowerShell (Windows) or Bash (Linux/macOS)

### 2. Environment Setup

```powershell
cd c:\Users\ASUS\zerotrust
.\.venv\Scripts\Activate.ps1
```

*(If setting up for the first time, packages are installed via `pip install -r requirements.txt`)*

### 3. Run the Backend API

```powershell
cd backend
..\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

- API Health Check: `http://127.0.0.1:8000/api/health`
- Interactive OpenAPI Docs: `http://127.0.0.1:8000/docs`
- Built Dashboard: `http://127.0.0.1:8000/dashboard/`

### 4. Run the Frontend (Vite Dev Server)

```powershell
cd frontend
npm run dev
```

Open your browser to: **`http://localhost:5173`**

### 5. Running Automated Backend Test Suite

```powershell
.\.venv\Scripts\python.exe -m pytest backend/tests/ -v
```

All 18 tests cover authentication, session lifecycle, token revocation, RBAC boundaries, risk inference, and policy enforcement.

---

## 🔑 Demo Credentials

| Role | Email | Password |
|------|-------|----------|
| **Administrator** | `admin@zerotrust.demo` | `AdminDemo!234` |
| **Standard User** | `user@zerotrust.demo` | `UserDemo!234` |

*Easily toggle between Administrator and Standard User directly from the top-right header in the frontend dashboard.*

---

## 📁 Repository Layout

```text
zerotrust/
├── backend/
│   ├── app/
│   │   ├── api/            # API routers (auth, sessions, health, audit)
│   │   ├── core/           # Security, JWT, rate limiting, dependencies
│   │   ├── models/         # SQLAlchemy ORM (user, session, event, risk, audit)
│   │   ├── schemas/        # Pydantic schemas
│   │   └── services/       # Risk engine, inference, policy, features, audit
│   └── tests/              # 18 Pytest unit & integration tests
├── frontend/
│   ├── src/
│   │   ├── components/     # RiskGauge, etc.
│   │   ├── App.jsx         # Multi-tab cybersecurity dashboard
│   │   ├── api.js          # API client with token management
│   │   └── index.css       # Obsidian & neon cyan glassmorphism design system
│   └── vite.config.js      # Vite dev server with /api proxy
├── ml/
│   ├── baselines/          # Static rule-based baseline
│   ├── artifacts/          # Trained models (.txt, .pt, .joblib), plots, metrics
│   ├── generate_synthetic.py # Domain-grounded session event generator
│   ├── preprocess.py       # GroupKFold session splitter and scaler
│   ├── train_lgbm.py       # LightGBM tabular trainer
│   ├── train_gru.py        # PyTorch GRU sequence trainer
│   ├── train_hybrid.py     # Logistic stacking & isotonic calibrator
│   └── run_phase5.py       # Orchestrator & benchmark comparator
└── requirements.txt        # Python dependency manifest
```
