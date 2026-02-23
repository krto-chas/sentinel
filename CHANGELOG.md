# CHANGELOG

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
- Added safer file input handling so the same file can be selected again after upload.

