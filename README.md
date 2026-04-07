# theintentlayer.com

FastAPI web application serving as the landing page, user auth, and OAuth 2.1 provider for The Intent Layer MCP connectors.

## Quick Start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # edit secrets
uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload
```

## Production

```bash
docker compose -f deployment/docker/docker-compose.prod.yml up -d
```
