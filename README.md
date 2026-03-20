# AI Community Guardian

- Candidate Name: Abhay Raghvendra Revankar.
- Scenario Chosen: Community Safety & Digital Wellness.
- Estimated Time Spent: 6 hours.

## Demo video link : https://youtu.be/5HY47fKFXHo

## Quick Start:

● Prerequisites:
  - Python 3.x installed
  - Virtual environment support (venv)
  - (Optional for AI) Create `.env` from `.env.example` and set `GEMINI_API_KEY`

● Run Commands:
  - Create venv (if not created):
    - `python -m venv .venv`
  - Install dependencies:
    - `.venv\Scripts\python -m pip install -r requirements.txt`
  - Start server:
    - `.venv\Scripts\python -m uvicorn main:app --host 127.0.0.1 --port 8000`
  - Open:
    - `http://127.0.0.1:8000/`

● Test Commands:
  - `.venv\Scripts\python -m pytest test_app.py -v`

## AI Disclosure:

● Did you use an AI assistant (Copilot, ChatGPT, etc.)? (Yes/No)
  - Yes
    
● How did you verify the suggestions?
  - I verified behavior by running the app through the UI routes and by running automated tests using `pytest`.
    
● Give one example of a suggestion you rejected or changed:
  - I considered storing raw user message history, but I changed the design to a privacy-first approach: storing only token fingerprints / aggregated behavior signals (no raw messages or personal data).

## Tradeoffs & Prioritization:

● What did you cut to stay within the 4–6 hour limit?
  - No database persistence (alerts/habits are in-memory).
  - Server-rendered HTML + vanilla JS instead of a separate frontend build.
  - Safe Circle uses demo-grade encryption (conceptual simulation) rather than production cryptography/key management.
● What would you build next if you had more time?
  - Persistence (SQLite/Postgres) for alerts and user habit profiles.
  - Strong cryptography (AES-GCM) + proper key handling for Safe Circle.
  - Real-time alerts (WebSockets/SSE) and richer alert filtering/search.
  - More robust anomaly detection and configurable thresholds.
● Known limitations:
  - Alerts and habits reset when the server restarts (in-memory).
  - AI calls may fail due to external rate limits (e.g., 429), so the system falls back to rule-based verification.
  - Safe Circle encryption is a demo simulation, not production-ready security.





-----



# **Zero Trust Cyber Safety Assistant** — A Community Guardian platform that aggregates digital security data, uses AI to filter noise, and provides calm, actionable safety digests.

---

## Submission Deliverables

| Requirement | Status |
|-------------|--------|
| Working Prototype/Demo | ✅ Web application (FastAPI + HTML) |
| Synthetic Dataset | ✅ `data.json` (no real personal data) |
| Design Documentation | ✅ `DESIGN.md` — design, tech stack, future enhancements |
| Completed README | ✅ This file |
| 5–7 Minute Video | 📹 Add your screen recording link/file (recording guide below) |
| Feature Documentation (PDF) | ✅ `features_implement.pdf` (features + detailed usage/examples) |

---

## Features

- **Multi-page UI:** Home, Analyze, Alerts, Safe Circle (all linked via navigation)
- **Threat Classification:** Phishing, scam, malware, or safe — with trust score, explanation, and actionable checklist
- **AI + Rule Fallback:** Gemini when available; deterministic rules when not
- **Spam Memory:** Learns token patterns from prior suspicious messages (privacy-first)
- **User Habits:** Detects unusual behavior (new location, atypical hour, alert spikes)
- **Alert Fatigue Reduction:** Filters to HIGH/MEDIUM only; deduplication; Refresh button
- **Safe Circle:** Encrypt status messages for trusted guardians; separate Encrypt and Decrypt sections
- **Elderly-Friendly Mode:** Simplified SAFE/NOT SAFE output

---

## Setup

1. **Clone the repository**

   ```bash
   git clone <your-repo-url>
   cd project_abhay
   ```

2. **Create a virtual environment**

   ```bash
   python -m venv .venv
   ```

3. **Install dependencies**

   ```bash
   .venv\Scripts\pip install -r requirements.txt
   ```
   (On macOS/Linux: `source .venv/bin/activate` then `pip install -r requirements.txt`)

4. **Configure environment (optional for AI)**

   - Copy `.env.example` to `.env`
   - Set `GEMINI_API_KEY` (get from [Google AI Studio](https://aistudio.google.com/app/apikey))
   - If not set, the app uses rule-based fallback automatically

---

## Run

```bash
.venv\Scripts\python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

Open: **http://127.0.0.1:8000/**

---

## Test

```bash
.venv\Scripts\python -m pytest test_app.py -v
```

- 7 tests: phishing classification, empty input rejection, alerts endpoint, spam memory, Safe Circle share/receive, wrong passphrase, user habits

---

## Synthetic Dataset

`data.json` contains sample messages and synthetic locations (Bangalore, Mumbai, Delhi). No real personal data. No external scraping.

---

## Project Structure

```
project_abhay/
├── main.py          # FastAPI app, routes, analyze logic
├── templates.py     # Shared CSS, nav, page layout
├── ai_engine.py     # Gemini classification (returns None on failure)
├── rules.py         # Rule-based fallback
├── zero_trust.py    # Combines AI + rules
├── spam_memory.py   # Token-based pattern learning
├── user_habits.py   # Per-user behavior model
├── actions.py       # Action checklists per threat
├── safe_circle.py   # Encryption for Safe Circle
├── data.json        # Synthetic dataset
├── test_app.py      # Tests
├── DESIGN.md        # Design, tech stack, future enhancements
├── .env.example     # API key template (do not commit .env)
└── requirements.txt
```

---

## Design & Tradeoffs

See **DESIGN.md** for full design documentation.

### Key Tradeoffs

| Tradeoff | Choice | Rationale |
|----------|--------|-----------|
| AI fallback | Rule-based patterns | Deterministic, always available, no API dependency |
| Data storage | In-memory | Demo-friendly; no DB setup |
| User context | Aggregated patterns only | Privacy-first; no raw message history |
| Habit model | Rule-based | Explainable, low latency |
| Encryption | Demo-grade (XOR) | Conceptual Safe Circle; not production crypto |

---

## Security

- Use `.env.example` as a template only

---

