Sentinel Upload API

![CI Status](https://github.com/Sidestep-Error/sentinel-upload-api/actions/workflows/ci.yml/badge.svg)

Minimal FastAPI app for secure file upload handling.

Docs index

- PLAN.md
- SECURITY.md
- GITHUB-BEST-PRACTICE.md
- docs/architecture.md
- docs/docker-mongo-port-guide.md
- docs/shared-responsibility.md
- sre/sli-slo.md
- runbooks/upload-api-unavailable.md
- sre/postmortem-template.md
- ToDo.md
- CHANGELOG.md
Git flow policy

- Default branch is `main` (stable/deployed).
- Ongoing development is done in `develop` and `feat/*` branches.
- Use PR + CI + review before merging.
- Merge `develop` -> `main` only for release-ready changes.

CI pipeline

- Triggers on pull requests and pushes to `main` and `develop`.
- Runs dependency vulnerability scanning with `pip-audit` on `app/requirements.txt`.
- Runs linting with `ruff` (`ruff check app tests`).
- Validates Kubernetes and Gatekeeper manifests using `kubeconform`.
- Runs tests with `pytest`.
- Runs matrix tests on Python `3.11` and `3.12`.
- Builds Docker image, runs Trivy scan (HIGH/CRITICAL), and generates SBOM (Syft artifact).
- Pushes Docker image to Docker Hub on `main` pushes after all checks pass.
- Docker Hub secrets required in GitHub: `DOCKER_USERNAME`, `DOCKER_PASSWORD` (token), `DOCKER_IMAGE` (e.g. `sidesteperror/sentinel-upload-api`).

Run locally (Docker)

```powershell
docker build -f docker/Dockerfile -t sentinel-upload-api:dev .
docker run --name sentinel -p 8000:8000 sentinel-upload-api:dev
```

Run locally with MongoDB (docker compose)

```powershell
# Local Docker Mongo mode
Copy-Item .env.local.example .env
docker compose up --build
```

Run with MongoDB Atlas connection string

```powershell
# Atlas mode
Copy-Item .env.atlas.example .env
# Edit .env and set MONGODB_URI to your Atlas URI
docker compose up --build
```

UI

- Open http://localhost:8080/
- Logo asset: app/static/assets/sidestep-logo.png
- Use the UI upload console to test /upload.
- Uploaded Files list is populated when MongoDB is running.
- Hosted demo (Render): https://sentinel-upload-api.onrender.com/

Nginx reverse proxy

- Nginx is now the public entrypoint in docker compose.
- FastAPI is internal-only in the compose network.
- Nginx host port is configurable (`NGINX_HOST_PORT`, default `8080`).

Nginx reverse proxy

- Nginx is now the public entrypoint in docker compose.
- FastAPI is internal-only in the compose network.
- Nginx host port is configurable (`NGINX_HOST_PORT`, default `8080`).

MongoDB

- Local mode: keep `MONGODB_URI` unset/commented so app uses local Mongo service.
- Atlas mode: set `MONGODB_URI` to Atlas `mongodb+srv://...` URI.
- In docker compose we use env-driven config for both modes.

MongoDB hardening updates (what changed and why)

- MongoDB now starts with username/password.
  - Why: prevents unauthenticated read/write access in local dev.
- App uses `MONGODB_URI` with credentials from environment variables.
  - Why: avoids hardcoded secrets and supports per-developer settings.
- MongoDB host port is configurable (`MONGO_HOST_PORT`, default `28017`).
  - Why: avoids conflicts on machines where `27017` is already used.
- MongoDB healthcheck is enabled and app waits for healthy DB before start.
  - Why: removes startup race conditions and reduces `Database unavailable` errors.
- If you changed local Mongo credentials after first startup, re-initialize local DB:
  - `docker compose down -v`
  - `docker compose up --build`

Health check

```powershell
curl http://localhost:8080/health
```

List uploads (requires MongoDB)

```powershell
curl http://localhost:8080/uploads
```

Upload (PowerShell)

```powershell
curl -F "file=@README.md;type=text/markdown" http://localhost:8080/upload
```

Security hardening (input validation)

The upload endpoint enforces server-side input validation to mitigate common web vulnerabilities:

| Vulnerability | Fix | File |
|---|---|---|
| **XSS via filename** – Upload list rendered filenames with `innerHTML`, allowing injected `<script>` tags to execute in visitors' browsers. | Replaced `innerHTML` with `textContent` (DOM API) so filenames are always rendered as plain text. | `app/static/index.html` |
| **Path traversal in filename** – Filenames like `../../etc/passwd` were stored and passed to the scanner without sanitisation. | New `sanitize_filename()` strips path components (`/` and `\`), rejects `.`/`..`, enforces a 255-char limit, and allows only `[a-zA-Z0-9_\-. ]`. | `app/main.py` |
| **Content-type spoofing** – The server trusted the client-supplied `Content-Type` header without verification, so a `.exe` could be uploaded as `text/plain`. | New `validate_content_type()` cross-checks the file extension against a per-type allowlist (`ALLOWED_EXTENSIONS`). Mismatches are rejected with HTTP 415. | `app/main.py` |

Tests covering these cases are in `tests/test_upload.py` (`test_upload_rejects_path_traversal_filename`, `test_upload_rejects_mismatched_extension`, `test_upload_rejects_invalid_characters_in_filename`, `test_upload_sanitizes_path_and_accepts_valid_file`).

Additional hardening (operational)

| Issue | Fix | File(s) |
|---|---|---|
| **Test deps in production image** – `pytest` and `httpx` were bundled in the Docker image, increasing attack surface. | Split into `requirements.txt` (prod) and `requirements-dev.txt` (test). Dockerfile only installs prod deps, tests directory no longer copied into image. CI workflows updated to use `requirements-dev.txt`. | `app/requirements.txt`, `app/requirements-dev.txt`, `docker/Dockerfile`, `.github/workflows/ci.yml`, `.github/workflows/pylint.yml` |
| **Rate limiter memory leak** – `_upload_request_times` dict never evicted inactive client IPs, growing unbounded over time. | Added stale-entry cleanup on each call: IPs with no activity within the rate-limit window are removed. | `app/main.py` |
| **Unbounded file read (DoS)** – `file.read()` loaded the entire upload into memory before checking the size limit. | Added early `Content-Length` header check plus a bounded `file.read(MAX + 1)` so at most 10 MB + 1 byte is ever buffered. | `app/main.py` |
| **Silent errors (no logging)** – All `except Exception` blocks swallowed errors without any trace, making debugging and incident response impossible. | Added Python `logging` with named logger `sentinel`. Logs upload accept/reject, scan details, DB failures, and rate-limit hits. | `app/main.py` |
| **No K8s health probes** – Deployment had no liveness or readiness probes despite `/health` endpoint existing. | Added `livenessProbe` and `readinessProbe` using `httpGet /health:8000`. | `k8s/base/deployment.yaml` |
| **Missing Nginx security headers** – Reverse proxy returned no security headers, allowing MIME sniffing, clickjacking, etc. | Added `X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection`, `Referrer-Policy`, `Permissions-Policy` and disabled `server_tokens`. | `docker/nginx/default.conf` |

Quality and infrastructure improvements

| Area | Change | File(s) |
|---|---|---|
| **Test coverage** | Added tests for file size limit (413) and `/uploads` endpoint (503 when DB unavailable). Total tests: 13. | `tests/test_upload.py` |
| **Test structure** | Extracted shared `client` fixture into `conftest.py` to remove duplication across test files. | `tests/conftest.py`, `tests/test_health.py`, `tests/test_upload.py` |
| **ClamAV healthcheck** | Added Docker Compose healthcheck so the app waits for ClamAV to be ready (`PING`/`PONG` check with 60 s start period). Previously the app could start before ClamAV was accepting connections. | `docker-compose.yml` |
| **NetworkPolicy** | Added K8s NetworkPolicy restricting ingress to the ingress controller and egress to DNS, ClamAV (3310), and MongoDB (27017). Added to CI kubeconform validation. | `k8s/base/networkpolicy.yaml`, `.github/workflows/ci.yml` |

Upload scanning behavior

- Files are scanned in-memory (no file content is persisted).
- MongoDB stores upload metadata and scan outcome (`scan_status`, `scan_engine`, `scan_detail`).
- Upload endpoint rate limiting is enabled (`10/minute` per client IP) to reduce burst uploads/abuse.
- Configure rate limit with `UPLOAD_RATE_LIMIT_PER_MINUTE` (default `10`) and `UPLOAD_RATE_LIMIT_WINDOW_SECONDS` (default `60`).
- In GitHub Actions CI, configure repo variables `UPLOAD_RATE_LIMIT_PER_MINUTE_CI` and `UPLOAD_RATE_LIMIT_WINDOW_SECONDS_CI` (workflow falls back to `120` and `60`).
- `SCANNER_MODE=auto` (default): try ClamAV first, fallback to mock scanner if ClamAV is unavailable.
- `SCANNER_MODE=clamav`: require ClamAV.
- `SCANNER_MODE=mock`: mock scanner only.
- Render free tier runs with `SCANNER_MODE=mock` (no private ClamAV service).
- Use local Docker Compose or Kubernetes when you need full ClamAV runtime scans.
- Mock scanner flags EICAR marker and suspicious filename patterns.
- Upload policy is fail-closed: non-clean scan results (`malicious` or `error`) are rejected.

Authentication (Firebase)

- Set `AUTH_MODE=firebase` to require Firebase ID token on `/upload` and `/uploads`.
- Set `FIREBASE_WEB_API_KEY=<your_web_api_key>` in environment (served by backend config endpoint).
- Send token as `Authorization: Bearer <firebase_id_token>`.
- Configure credentials using one of:
  - `FIREBASE_CREDENTIALS_FILE=/path/to/service-account.json`
  - `FIREBASE_CREDENTIALS_JSON='{"type":"service_account", ...}'`
- Default mode is `AUTH_MODE=off` (no auth required).
- The web UI includes an Auth Console for create account/login without manually entering API keys.

CI troubleshooting (rate limit)

- If CI gets unexpected `429` responses, increase `UPLOAD_RATE_LIMIT_PER_MINUTE_CI` (start with `120`, then `300` for bursty test runs).
- Keep `UPLOAD_RATE_LIMIT_WINDOW_SECONDS_CI=60` unless you need a shorter/longer evaluation window.
- If CI should mimic production behavior, set CI variables to the same values as production env vars.
- The rate-limit test overrides limiter constants in-test, so CI variable tuning should not break that test.

Publish on a subdomain (production outline)

1. Create DNS record:
   - Add `A` record: `api.yourdomain.com -> <your server public IP>`.
2. Run the app stack on the server:
   - `docker compose up -d --build`
3. Expose HTTP/HTTPS on the server:
   - Map Nginx to `80:80` for production (set `NGINX_HOST_PORT=80`), and terminate TLS.
4. Enable TLS:
   - Option A: put Caddy/Traefik in front for automatic Let's Encrypt.
   - Option B: keep Nginx and use certbot to manage certificates.
5. Security baseline:
   - Keep `.env` only on server (never commit secrets).
   - Restrict firewall to ports `80/443` only.

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




