# Audio Visualizer Backend (FastAPI)

FastAPI backend for authentication (JWT) and storing audio visualizer configurations.

## Environment Variables (set via .env)

- JWT_SECRET_KEY: Secret key for signing JWTs
- JWT_ALGORITHM: Default HS256
- JWT_ACCESS_TOKEN_EXPIRE_MINUTES: Token TTL minutes (default 120)
- FRONTEND_ORIGINS: Allowed CORS origins, comma-separated (default http://localhost:3000)

Database (provided by database container):
- POSTGRES_URL (preferred) OR:
  - POSTGRES_USER
  - POSTGRES_PASSWORD
  - POSTGRES_DB
  - POSTGRES_HOST (default localhost)
  - POSTGRES_PORT (default 5432)

Note: Do not commit .env. Orchestrator will set these in CI/runtime.

## Run locally

- Install dependencies: `pip install -r requirements.txt`
- Run dev: `uvicorn src.api.main:app --reload --host 0.0.0.0 --port 3001`

Open: http://localhost:3001/docs

## API

- POST /auth/signup
- POST /auth/login (OAuth2 password flow; fields: username, password)
- GET /users/me
- PATCH /users/me
- POST /visualizer/configs
- GET /visualizer/configs
- GET /visualizer/configs/{config_id}
- PATCH /visualizer/configs/{config_id}
- DELETE /visualizer/configs/{config_id}

```
