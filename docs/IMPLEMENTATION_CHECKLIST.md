# Implementation Checklist

**Project:** Zero-Trust Access Control Framework Using Continuous Risk Assessment  
**Stack:** FastAPI + PostgreSQL + React/Vite + LightGBM + PyTorch GRU + Hybrid fusion  
**Status key:** `[ ]` pending · `[~]` in progress · `[x]` done · `[-]` deferred/N/A

---

## Phase 1 — Repository & scaffolding

- [x] Inspect repository (empty workspace confirmed)
- [x] Confirm toolchain (Python 3.12, Node 25, Docker; no local `psql` — use Docker Postgres)
- [x] Create project layout, `.gitignore`, `.env.example`, `requirements.txt`
- [x] Write this checklist
- [x] Document Windows-local setup approach

## Phase 2 — Backend foundation & database

- [x] FastAPI application entrypoint (`backend/app/main.py`)
- [x] Settings via environment (`config.py`)
- [x] SQLAlchemy engine / session factory
- [x] Core ORM models (users, roles, sessions, events, risk, decisions, audit, model versions)
- [x] Alembic initialization and initial migration
- [x] `GET /api/health` endpoint
- [x] `docker-compose.yml` for PostgreSQL 16 (host port **5433**)
- [x] Verify health endpoint against live DB (`status=ok`, `database=up`)
- [x] Smoke test with pytest (`2 passed`)

## Phase 3 — Auth, RBAC, sessions

- [x] Register / login / me endpoints
- [x] Argon2id password hashing (`pwdlib` recommended hasher)
- [x] JWT issue + validation + expiry (+ user `token_version`)
- [x] Role-based authorization (admin / analyst / user)
- [x] Server-side session create/list/get
- [x] Session token version / revocation checks (`stv` claim + status)
- [x] Auth rate limiting (in-memory sliding window)
- [x] Seeded demo accounts (dev only; `@zerotrust.demo`)
- [x] Tests: register, login, invalid creds, JWT, RBAC, sessions (**13 passed**)

## Phase 4 — Dataset & preprocessing

- [ ] Survey public datasets; document suitability
- [ ] Synthetic dataset generator (documented; not claimed as real-world validation)
- [ ] Schema validation, encoding, normalization
- [ ] Session-level train/val/test split (no leakage)
- [ ] Class imbalance documentation
- [ ] Rule-based baseline evaluation script

## Phase 5 — LightGBM & GRU/LSTM

- [ ] Feature documentation
- [ ] LightGBM training + artifacts
- [ ] GRU sequence model (PyTorch) + artifacts
- [ ] Validation-based early stopping / hyperparams
- [ ] Metrics: Precision, Recall, F1, PR-AUC, ROC-AUC, CM, FPR/FNR, latency

## Phase 6 — Hybrid fusion

- [ ] Leakage-safe OOF / validation predictions
- [ ] Logistic stacking (or documented alternative)
- [ ] Probability calibration on validation
- [ ] Compare hybrid vs individuals; retain strongest justified model
- [ ] Record whether hybrid improves (honest result)

## Phase 7 — Risk engine & policy integration

- [ ] Model loading + inference service
- [ ] Feature extraction from live session events
- [ ] Risk score 0–100 with documented mapping
- [ ] Configurable policy thresholds
- [ ] Adaptive decisions (allow / limit / step-up / deny / revoke)
- [ ] Hysteresis / cooldown
- [ ] Authorization never overridden by low risk
- [ ] Audit + access decision records
- [ ] Wire session event → assess → policy → audit pipeline
- [ ] Revocation enforcement on protected routes

## Phase 8 — React dashboard

- [ ] Vite + React scaffolding
- [ ] Login, overview, sessions, risk detail, decisions, audit, admin
- [ ] Demo mode (normal vs suspicious) clearly labeled simulated
- [ ] Loading / empty / error states
- [ ] Backend-only enforcement (frontend display only)

## Phase 9 — Tests & experiments

- [ ] Unit + API tests listed in master prompt §16
- [ ] End-to-end suspicious-activity scenario test
- [ ] Experimental evaluation script + plots
- [ ] Behavioral drift / detection-delay evaluation
- [ ] Execute tests; report actual pass/fail

## Phase 10 — Documentation & demo

- [ ] README (Windows setup: Docker DB, backend, frontend, ML)
- [ ] Architecture diagram
- [ ] Methodology flowchart
- [ ] API docs (OpenAPI + written summary)
- [ ] Report section: contribution, method, results, limitations, future work
- [ ] Reproducible demo script for viva/presentation

---

## Acceptance criteria mapping

| # | Criterion | Phase |
|---|-----------|-------|
| 1 | App runs locally | 2–8 |
| 2 | Auth + RBAC | 3 |
| 3 | Session events validated | 3, 7 |
| 4 | Reproducible ML risk estimates | 5–7 |
| 5 | Adaptive policy decisions | 7 |
| 6 | Continuous reassessment | 7–8 |
| 7 | Revocation enforced | 3, 7 |
| 8 | Audit UI | 7–8 |
| 9 | Model evaluation protocol | 4–6, 9 |
| 10 | Honest results + limitations | 9–10 |
| 11 | Normal + suspicious demo | 8, 10 |
| 12 | Setup docs + automated tests | 9–10 |

---

## Decisions locked for Phase 1–2

1. **Database:** PostgreSQL 16 via Docker Compose on host port **5433** (avoids conflict with other local Postgres on 5432).
2. **Password hashing:** `pwdlib` with Argon2id (Phase 3).
3. **ORM:** SQLAlchemy 2.x + Alembic.
4. **API prefix:** `/api`.
5. **Primary ML contribution target:** hybrid fusion of LightGBM + GRU; if hybrid does not improve, document and ship the strongest model.
6. **Dataset:** investigate public options in Phase 4; fall back to documented synthetic data if unsuitable.
7. **psycopg:** use `psycopg` v3 (`psycopg[binary]==3.2.3`) with `postgresql+psycopg://` URLs.

## Phase 2 verification log (actual)

| Check | Result |
|-------|--------|
| `docker compose up -d` | healthy on port 5433 |
| `alembic upgrade head` | created 9 domain tables + `alembic_version` |
| `pytest backend/tests` | **2 passed** |
| `GET /api/health` | `{"status":"ok","database":"up",...}` |
