# syntax=docker/dockerfile:1

FROM python:3.12-alpine

# Bas-säkerhet: mindre attackyta + stabilt beteende
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Uppdatera OS-paket för säkerhetsfixar
RUN apk update && apk upgrade

# Skapa en icke-root user
RUN addgroup -S app && adduser -S app -G app

WORKDIR /app

# Installera enbart produktionsberoenden (test-deps finns i requirements-dev.txt)
COPY app/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Kopiera enbart appkod (tester behövs inte i produktionsimage)
COPY app/ /app/app/

# Byt till non-root
USER app

EXPOSE 8000

# Kör Uvicorn (FastAPI)
CMD ["sh", "-c", "python -m uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
