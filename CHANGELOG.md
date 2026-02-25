# CHANGELOG

<<<<<<< HEAD
=======
## 2026-02-25

- Produced hardened `docker-compose.yml` for Hetzner production deployment replacing the development-oriented compose configuration.
- Applied `cap_drop: ALL` with minimal capability allowlists on all containers (nginx, api, mongodb).
- Enabled `no-new-privileges: true` on all containers to prevent privilege escalation via SUID/SGID binaries.
- Set `read_only: true` on nginx and api containers with `tmpfs` mounts for paths that require write access (`/tmp`, `/var/cache/nginx`, `/var/run`, `/app/tmp`).
- Added CPU and memory resource limits and reservations on all containers to prevent resource exhaustion.
- Introduced isolated Docker networks: `frontend` (nginx ↔ api) and `backend` (api ↔ mongodb, api ↔ clamav). Backend network is `internal: true`, blocking all external egress.
- Removed host-port binding for MongoDB in production configuration. Port `27017` is exposed only within the backend network via `expose`, not `ports`.
- Added named volumes `mongodb_data` and `clamav_db` for persistent storage with clear backup surface.
- Switched ClamAV image from `clamav/clamav:1.4-debian` (non-existent tag) to `clamav/clamav-debian:stable` (correct Debian-based repository).
- Replaced ClamAV healthcheck script (`/usr/local/bin/clamdcheck.sh`, Alpine-specific) with a portable `nc`-based PING/PONG check compatible with the Debian image.
- Extended ClamAV healthcheck `start_period` to `300s` to accommodate initial signature database download on first start.
- Removed `cap_drop` from ClamAV service as its entrypoint requires root to set directory ownership before internally dropping privileges.
- Added `daemon.json` configuration for the Hetzner Docker daemon: `no-new-privileges`, `icc: false` (disables inter-container communication outside defined networks), `live-restore: true`, `userland-proxy: false`, and log rotation (`max-size: 10m`, `max-file: 3`).
- Produced hardened `Dockerfile` with non-root `appuser` (uid/gid 1000), split production/dev requirements, no test files copied into image, and build-time ownership set correctly for `/app` and `/app/tmp`.
- Documented that `daemon.json` applies to the Hetzner Linux server only and must not be applied to local Docker Desktop on Windows.
- Documented that GitHub Actions secrets are CI-only and do not substitute for a local `.env` file during development.

>>>>>>> f329656 (Initial commit)
## 2026-02-23

- Added safer ThreatFox secret handling: `THREATFOX_API_KEY_FILE` support plus documented Secret-first usage across local/Kubernetes.
- Added threat-intel policy controls for volume/risk tuning: `THREAT_INTEL_ALLOWED_SOURCES`, `THREAT_INTEL_MIN_CONFIDENCE`, `THREAT_INTEL_MAX_EVENTS_PER_RUN`.
- Updated ingestion job to apply source allowlist and confidence/volume filtering before DB writes.
- Replaced mutable `latest` image references in runtime manifests with explicit non-`latest` tags.
- Documented GeoIP limitations in README to clarify that map positions are approximate and non-attributive.

## 2026-02-21

- Added threat-intel feed expansion: Feodo + URLhaus + ThreatFox ingestion pipeline in `app/services/threat_intel.py`.
- Added map clustering and richer threat popup details in the UI.
- Added ThreatFox API compatibility guard (`THREATFOX_DAYS` clamped to 1..7).
- Added URLhaus shape handling for multiple JSON response variants.
- Security hardening lesson applied: hostname-to-IP DNS resolution is now disabled by default (`THREAT_RESOLVE_DOMAINS=false`) to reduce unintended outbound DNS lookups to suspicious IOC domains.

## 2026-02-18

- Replaced hero image panel with cyber threat feed panel powered by backend endpoint `/external/threats/kev-summary` (CISA KEV).
- Added backend CISA KEV proxy with cache/rate-limit guard and explicit `User-Agent` header.
- Added upload list UX guardrails: default list limit (`25`) and scrollable Uploaded Files panel.
- Added MongoDB indexes for uploads: `sha256` index and TTL retention index on `created_at` (`UPLOAD_RETENTION_DAYS`, default 30).
- Added metrics summary endpoint `GET /metrics/summary` with 24h/7d/all-time trend aggregates.
- Updated frontend cards to show live trend metrics (uploads, rejected, rejection rate, average risk).
- Added upload risk scoring (`risk_score`) and explicit decision field (`decision`: accepted/review/rejected).
- Added risk reasons metadata (`risk_reasons`) in upload responses and MongoDB records.
- Added SHA-256 hashing for uploads and deduplication flow (`deduplicated=true` on repeated content).
- Updated UI Virus Scanning panel to show decision, risk score, and deduplication status.
- Enabled HTTPS for `sentinel-upload.secion.se` using cert-manager and Let's Encrypt (`ClusterIssuer: letsencrypt-prod`).
- Updated ingress TLS configuration to issue/store certificate in `sentinel-upload-tls`.
- Verified successful certificate issuance (`Certificate READY=True`) and HTTPS health endpoint responses.
- Removed Firebase auth from API/UI flow to reduce attack surface for the current no-login use case.
- Updated upload/list endpoints to run without bearer tokens and removed Firebase client logic from the frontend.
- Switched Kubernetes app config to `AUTH_MODE=off` and removed Firebase keys from `k8s/base/secret.example.yaml`.

## 2026-02-17

- Finalized Kubernetes ingress path on VPS by standardizing on `ingress-nginx` (single active ingress controller).
- Updated `k8s/base/ingress.yaml` to use `ingressClassName: nginx` and backend service port `8000`.
- Updated `k8s/base/service.yaml` to `port: 8000` / `targetPort: 8000` for consistent routing.
- Updated `k8s/base/networkpolicy.yaml` ingress rules to allow traffic from `ingress-nginx` namespace/controller to API port `8000`.
- Added `nginx.ingress.kubernetes.io/service-upstream: "true"` annotation to route through Service ClusterIP and resolve repeated `502 Bad Gateway` caused by unreachable direct pod upstreams.

## 2026-02-11

- Documented Render deployment URL and clarified scanner mode strategy (mock on Render free tier, clamav in local/K8s).
- Added an upload mock scanner (`app/scanner.py`) to detect malicious signatures without storing file content.
- Added ClamAV service integration in Docker Compose with scanner modes (`auto`, `clamav`, `mock`).
- Extended upload metadata model with scan fields (`scan_status`, `scan_engine`, `scan_detail`).
- Updated `/upload` flow to scan in memory, enforce max file size, and persist scan result metadata in MongoDB.
- Enforced fail-closed upload policy for scanner errors (`status=rejected` when `scan_status=error`).
- Added upload tests for clean, malicious, and scanner-error paths.

## 2026-02-07

- Added Nginx reverse proxy service in Docker Compose as public entrypoint (`NGINX_HOST_PORT`).
- Added Atlas/local environment mode templates (`.env.atlas.example`, `.env.local.example`).
- Updated app startup to respect `PORT` for Render compatibility.
- Improved Mongo DB selection fallback in `app/db.py` when URI has no default database path.
- Updated deployment docs for Docker Compose, Atlas usage, and Render flow.

## 2026-02-03

- Implemented MongoDB-backed upload metadata flow in the API (`/upload` stores metadata, `/uploads` lists records).
- Added Docker Compose support for app + MongoDB and documented local startup with compose.
- Hardened MongoDB runtime setup with env-driven credentials, healthcheck, and app startup dependency on healthy DB.
- Added `.env.example` and updated docs (`README.md` and `docs/docker-mongo-port-guide.md`) with port/auth best practices.
- Resolved host port conflict strategy by exposing MongoDB on `28017` while keeping internal container communication on `27017`.

## 2026-02-02

- Identified a UI bug where the file picker could open twice for some users.
- Patched `app/static/index.html` to prevent double-trigger from dropzone/label clicks.
<<<<<<< HEAD
- Added safer file input handling so the same file can be selected again after upload.

=======
- Added safer file input handling so the same file can be selected again after upload.
>>>>>>> f329656 (Initial commit)
