# =============================================================================
# sentinel-upload-api — Härdad Dockerfile
# =============================================================================
# Säkerhetsåtgärder:
#   - Pinnad bas-image med specifik version (inte bara "slim")
#   - Non-root appuser (uid/gid 10001 > 10000 – uppfyller CKV_K8S_40)
#   - Bara produktionsberoenden installeras (requirements.txt, ej requirements-dev.txt)
#   - Testfiler och utvecklingsverktyg kopieras INTE in i imagen
#   - Minimal filsystemsyta — bara det som behövs för runtime
# =============================================================================

FROM python:3.12-slim-bookworm

# Metadata
LABEL maintainer="sentinel-upload-api"
LABEL org.opencontainers.image.description="Secure file upload API with ClamAV scanning"

# Miljövariabler för Python
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Installera curl (för healthcheck) och rensa apt-cache direkt
# Versionspinning undviks avsiktligt – säkerhetsuppdateringar hanteras via Trivy.
# hadolint ignore=DL3008
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

# Skapa non-root user och grupp
# uid/gid 10001 matchar K8s runAsUser/runAsGroup och docker-compose user: "10001:10001"
# Värdet > 10000 uppfyller Checkov CKV_K8S_40 (avoid host UID conflict).
RUN groupadd --gid 10001 appuser && \
    useradd --uid 10001 --gid appuser --shell /bin/bash --create-home appuser

# Skapa workdir och sätt äganderätt
WORKDIR /app
RUN chown appuser:appuser /app

# Kopiera och installera beroenden som root (pip behöver skrivaccess)
COPY app/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Kopiera applikationskod (utan tests, dev-config etc.)
COPY --chown=appuser:appuser app/ ./app/

# Skapa tmp-mapp som appuser kan skriva till
# (docker-compose mountar tmpfs hit, men bra att ha som fallback)
RUN mkdir -p /app/tmp && chown appuser:appuser /app/tmp

# Byt till non-root user för allt som följer
USER appuser

# Exponera port (dokumentation, ej faktisk portbindning)
EXPOSE 8000

# Healthcheck i imagen (docker-compose overridar med sin healthcheck)
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

# Starta applikationen
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
