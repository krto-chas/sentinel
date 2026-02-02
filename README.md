Sentinel Upload API

Minimal FastAPI app for secure file upload handling.

Docs index

- PLAN.md
- SECURITY.md
- GITHUB-BEST-PRACTICE.md
- docs/architecture.md
- docs/shared-responsibility.md
- sre/sli-slo.md
- runbooks/upload-api-unavailable.md
- sre/postmortem-template.md
- ToDo.md

Run locally (Docker)

```powershell
docker build -f docker/Dockerfile -t sentinel-upload-api:dev .
docker run --name sentinel -p 8000:8000 sentinel-upload-api:dev
```

Run locally with MongoDB (docker compose)

```powershell
docker compose up --build
```

UI

- Open http://localhost:8000/
- Logo asset: app/static/assets/sidestep-logo.png
- Use the UI upload console to test /upload.
- Uploaded Files list is populated when MongoDB is running.

MongoDB

- Set MONGODB_URI to enable storage.
- Example: mongodb://localhost:27017/sentinel_upload

Health check

```powershell
curl http://localhost:8000/health
```

List uploads (requires MongoDB)

```powershell
curl http://localhost:8000/uploads
```

Upload (PowerShell)

```powershell
curl -F "file=@README.md;type=text/markdown" http://localhost:8000/upload
```

Expected response

Optional: Run locally (venv)

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r app/requirements.txt
uvicorn app.main:app --reload
```

```json
{"filename":"README.md","content_type":"text/markdown","status":"accepted"}
```
