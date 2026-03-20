# Design Documentation — AI Community Guardian

## Problem Statement

Digital and physical security threats are increasingly complex. Individuals struggle with scattered safety information across news and social media, leading to alert fatigue or anxiety without actionable steps. The **Community Guardian** platform aggregates local safety and digital security data, uses AI to filter noise, and provides calm, actionable safety digests.

## Target Audience

- **Neighborhood Groups** — Track local trends without social media toxicity
- **Remote Workers** — Monitor network security and home safety concerns
- **Elderly Users** — Simplified alerts for scams and hazards (elderly-friendly mode)

## Design Overview

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Web Browser                               │
│  Home | Analyze | Alerts | Safe Circle (multi-page UI)           │
└───────────────────────────┬─────────────────────────────────────┘
                            │ HTTP / Fetch
┌───────────────────────────▼─────────────────────────────────────┐
│                     FastAPI Backend                              │
│  /  /analyze-page  /alerts-page  /safe-circle-page               │
│  POST /analyze  GET /alerts  POST /safe-circle/share|receive     │
└───────────────────────────┬─────────────────────────────────────┘
                            │
    ┌───────────────────────┼───────────────────────┐
    │                       │                       │
    ▼                       ▼                       ▼
┌─────────┐          ┌─────────────┐         ┌─────────────┐
│ AI      │          │ Rules       │         │ Spam Memory │
│ (Gemini)│          │ (patterns)  │         │ (tokens)    │
└────┬────┘          └──────┬──────┘         └──────┬──────┘
     │                      │                       │
     └──────────────────────┼───────────────────────┘
                            ▼
                    ┌───────────────┐
                    │ Zero Trust    │
                    │ Combine       │
                    └───────┬───────┘
                            │
     ┌──────────────────────┼──────────────────────┐
     ▼                      ▼                      ▼
┌─────────────┐      ┌─────────────┐      ┌─────────────┐
│ User Habits │      │ Actions     │      │ Safe Circle │
│ (context)   │      │ (checklist) │      │ (encrypt)   │
└─────────────┘      └─────────────┘      └─────────────┘
```

### Core Flow

1. **Create** — User pastes a message on the Analyze page → `POST /analyze` classifies it and creates an alert
2. **View** — User opens the Alerts page → `GET /alerts` returns filtered HIGH/MEDIUM alerts (with Refresh)
3. **Update** — User habits and spam memory update on each analysis (adaptive learning)

### AI Integration + Fallback

- **Primary:** Google Gemini API classifies text (category, summary, confidence, reason)
- **Fallback:** Rule-based pattern matching (`rules.py`) when AI is unavailable (e.g., 429 rate limit, no API key)
- **Zero Trust:** Combines AI (60%) and rules (40%) — never trusts AI blindly

## Tech Stack

| Component | Technology |
|-----------|------------|
| Backend | FastAPI |
| Server | Uvicorn (ASGI) |
| AI | Google Gemini API (optional) |
| Validation | Pydantic |
| HTTP Client | Requests (Gemini), httpx (tests) |
| Env | python-dotenv |
| Tests | pytest |
| Frontend | Server-rendered HTML + vanilla JS (no build step) |

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| Server-rendered HTML | No frontend build; easy to run and demo |
| In-memory storage | Demo-friendly; no database setup |
| Synthetic data only | No scraping; `data.json` for locations |
| Token fingerprints | Privacy-first; no raw message storage |
| Rule-based habits | Explainable; low latency; demo-appropriate |

## Future Enhancements

1. **Persistence** — SQLite or PostgreSQL for alerts and habit profiles
2. **Authentication** — User accounts for personalized dashboards
3. **Real-time alerts** — WebSocket or SSE for live notification updates
4. **Local news integration** — RSS/APIs (with consent) for regional threat feeds
5. **Stronger encryption** — AES-256 for Safe Circle instead of demo-grade XOR
6. **Mobile app** — React Native or Flutter for on-the-go alerts
7. **ML-based habits** — Replace rule-based anomaly detection with lightweight models
