<<<<<<< HEAD
# syntax=docker/dockerfile:1

FROM python:3.12-alpine

# Bas-säkerhet: mindre attackyta + stabilt beteende
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Uppdatera OS-paket för säkerhetsfixar
RUN apk update && apk upgrade

# Skapa en icke-root user med fast UID/GID (kravs av vissa Kubernetes-policies)
RUN addgroup -g 10001 -S app && adduser -S -u 10001 -G app app

WORKDIR /app

# Installera enbart produktionsberoenden (test-deps finns i requirements-dev.txt)
COPY app/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Kopiera enbart appkod (tester behövs inte i produktionsimage)
COPY app/ /app/app/

# Byt till non-root med numerisk UID/GID
USER 10001:10001

EXPOSE 8000

# Kopiera GeoLite2-databasen (som inte är i .gitignore) till image:en
COPY assets/GeoLite2-City.mmdb /app/assets/GeoLite2-City.mmdb

# Kör Uvicorn (FastAPI)
CMD ["sh", "-c", "python -m uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
=======
# =============================================================================
# sentinel-upload-api — Härdad Dockerfile
# =============================================================================
# Säkerhetsåtgärder:
#   - Pinnad bas-image med specifik version (inte bara "slim")
#   - Non-root appuser (uid 1000)
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
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

# Skapa non-root user och grupp
# uid/gid 1000 matchar docker-compose user: "1000:1000"
RUN groupadd --gid 1000 appuser && \
    useradd --uid 1000 --gid appuser --shell /bin/bash --create-home appuser

# Skapa workdir och sätt äganderätt
WORKDIR /app
RUN chown appuser:appuser /app

# Kopiera och installera beroenden som root (pip behöver skrivaccess)
COPY app/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Kopiera applikationskod (utan tests, dev-config etc.)
COPY app/ ./app/
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
>>>>>>> f329656 (Initial commit)
