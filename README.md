# Audio Visualizer Platform

Multi-container application:
- Backend (FastAPI) on port 3001
- Database (PostgreSQL) on port 5001 (not directly accessed by users)
- Frontend (React) on port 3000

## Local Development

Backend:
- cd audio_visualizer_backend
- Create .env with required variables
- pip install -r requirements.txt
- uvicorn src.api.main:app --reload --host 0.0.0.0 --port 3001

Frontend:
- cd ../audio_visualizer_frontend
- cp .env.example .env
- npm install
- npm start

## Environment Variables

Backend (.env):
- JWT_SECRET_KEY=your_secret
- JWT_ALGORITHM=HS256
- JWT_ACCESS_TOKEN_EXPIRE_MINUTES=120
- FRONTEND_ORIGINS=http://localhost:3000
- POSTGRES_URL=postgresql://USER:PASS@HOST:PORT/DB  (or use parts POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_DB, POSTGRES_HOST, POSTGRES_PORT)

Frontend (.env):
- REACT_APP_API_BASE=http://localhost:3001