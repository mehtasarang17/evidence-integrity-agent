# 🛡️ Evidence Integrity Agent

An **AI-powered multi-agent system** that verifies the authenticity of digital evidence — screenshots, logs, and documents — using **LangChain, LangGraph, LangSmith, RAG**, and a stunning dark-themed frontend.

## Architecture

```
┌──────────────┐     ┌──────────┐     ┌──────────────┐
│Metadata Agent│     │Hash Agent│     │ Visual Agent  │
└──────┬───────┘     └────┬─────┘     └──────┬───────┘
       │                  │                   │
       └────────┬─────────┘                   │
                │                             │
       ┌────────▼─────────────────────────────▼─┐
       │         RAG Pattern Agent               │
       └────────────────┬───────────────────────┘
                        │
       ┌────────────────▼───────────────────────┐
       │      Report Generation Agent            │
       └────────────────┬───────────────────────┘
                        │
                   Final Report
         (Score, Risk Level, Findings)
```

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **AI Orchestration** | LangGraph + LangChain |
| **LLM** | OpenAI GPT-4o (with vision) |
| **RAG** | PostgreSQL + pgvector |
| **Observability** | LangSmith |
| **Backend** | Python Flask |
| **Frontend** | Vanilla HTML/CSS/JS |
| **Deployment** | Docker Compose |

## Quick Start

### 1. Clone & Configure

```bash
cp .env.example .env
# Edit .env and add your OPENAI_API_KEY
```

### 2. Run with Docker

```bash
docker-compose up --build
```

### 3. Access

- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:5000
- **Health Check**: http://localhost:5000/api/health

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/health` | Service health check |
| `POST` | `/api/upload` | Upload evidence file |
| `POST` | `/api/analyze` | Trigger analysis pipeline |
| `GET` | `/api/results/:id` | Get analysis results |
| `GET` | `/api/history` | List past analyses |

## Project Structure

```
evidence-integrity-agent/
├── docker-compose.yml          # 3 services: backend, frontend, postgres
├── backend/
│   ├── app.py                  # Flask API
│   ├── config.py               # Environment configuration
│   ├── agents/                 # LangGraph agent modules
│   │   ├── graph.py            # StateGraph workflow
│   │   ├── state.py            # Shared state schema
│   │   ├── metadata_agent.py   # EXIF & metadata analysis
│   │   ├── hash_agent.py       # SHA-256/MD5 verification
│   │   ├── visual_agent.py     # GPT-4o vision + ELA
│   │   ├── rag_agent.py        # Knowledge base search
│   │   └── report_agent.py     # Final report synthesis
│   ├── rag/                    # RAG system
│   │   ├── models.py           # SQLAlchemy + pgvector models
│   │   ├── vector_store.py     # Vector similarity search
│   │   └── knowledge_base.py   # Seed data loader
│   └── utils/                  # File, hash, image utilities
├── frontend/
│   ├── index.html              # SPA with 4 sections
│   ├── css/styles.css          # Dark theme + glassmorphism
│   └── js/                     # App, upload, dashboard, animations
└── .env.example                # Environment template
```

## License

MIT
