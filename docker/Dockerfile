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

# Installera dependencies först för bättre cache
COPY app/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Kopiera appkod + tester (för att kunna köra containern lokalt med samma innehåll)
COPY app/ /app/app/
COPY tests/ /app/tests/

# Byt till non-root
USER app

EXPOSE 8000

# Kör Uvicorn (FastAPI)
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
