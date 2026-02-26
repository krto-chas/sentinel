# Sentinel — Prometheus Metrics

Sentinel exponerar metrics i [Prometheus text format](https://prometheus.io/docs/instrumenting/exposition_formats/)
via endpointen `GET /metrics`. Endpointen är exkluderad från applikationens egna
HTTP-instrumentering för att undvika cirkulär mätning.

---

## Endpoint

```
GET /metrics
```

Returnerar alla registrerade metrics i Prometheus text format (Content-Type: `text/plain; version=0.0.4`).
Endpointen är inte inkluderad i OpenAPI-schemat (`include_in_schema=False`) och kräver ingen autentisering —
begränsa åtkomst via NetworkPolicy eller ingress-regler i Kubernetes.

**Exempel:**
```bash
curl http://localhost:8000/metrics
```

---

## Custom business metrics

Dessa metrics är definierade i `app/main.py` och reflekterar affärslogikens tillstånd.

### `sentinel_uploads_total`

| Egenskap | Värde |
|----------|-------|
| Typ | Counter |
| Beskrivning | Totalt antal filuppladdningar som processats sedan appstarten |

**Labels:**

| Label | Möjliga värden | Beskrivning |
|-------|---------------|-------------|
| `status` | `accepted`, `rejected` | Fail-closed status baserat på scan-resultat |
| `decision` | `accepted`, `review`, `rejected` | Riskbaserat beslut (risk_score < 30 / 30–69 / ≥ 70) |
| `engine` | `clamav`, `mock` | Vilken skanningsmotor som användes |

**Exempel på PromQL:**

```promql
# Uppladdningstakt per minut (senaste 5 min)
rate(sentinel_uploads_total[5m]) * 60

# Andel avvisade uppladdningar (%)
sum(rate(sentinel_uploads_total{status="rejected"}[5m]))
  / sum(rate(sentinel_uploads_total[5m])) * 100

# Antal upladdningar per beslutskategori
sum by (decision) (sentinel_uploads_total)

# Antal uppladdningar per skanningsmotor
sum by (engine) (sentinel_uploads_total)
```

---

### `sentinel_risk_score`

| Egenskap | Värde |
|----------|-------|
| Typ | Histogram |
| Beskrivning | Distribution av riskpoäng för uppladdade filer (0–100) |
| Buckets | 0, 10, 20, 30, 50, 70, 90, 100 |

Riskpoängen beräknas av `compute_risk()` baserat på scan-status, filnamn,
filstorlek och skanningsmotor. Gränser: < 30 = accepted, 30–69 = review, ≥ 70 = rejected.

**Exempel på PromQL:**

```promql
# Medelvärde för riskpoäng (senaste 10 min)
rate(sentinel_risk_score_sum[10m]) / rate(sentinel_risk_score_count[10m])

# 90:e percentilen för riskpoäng
histogram_quantile(0.90, rate(sentinel_risk_score_bucket[10m]))

# Andel filer med riskpoäng >= 70 (hög risk)
sum(rate(sentinel_risk_score_bucket{le="70"}[5m]))
  / sum(rate(sentinel_risk_score_count[5m]))
```

---

### `sentinel_scan_duration_seconds`

| Egenskap | Värde |
|----------|-------|
| Typ | Histogram |
| Beskrivning | Tid i sekunder för att skanna en uppladdad fil |
| Buckets | 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0 |

Mäter enbart skanningstiden (`scan_bytes()`), inte nätverks- eller databasoperationer.

**Exempel på PromQL:**

```promql
# Median skanntid (p50)
histogram_quantile(0.50, rate(sentinel_scan_duration_seconds_bucket[5m]))

# 99:e percentilen — identifiera outliers
histogram_quantile(0.99, rate(sentinel_scan_duration_seconds_bucket[5m]))

# Genomsnittlig skanntid
rate(sentinel_scan_duration_seconds_sum[5m])
  / rate(sentinel_scan_duration_seconds_count[5m])

# Alert: skanntid p95 > 2 sekunder
histogram_quantile(0.95, rate(sentinel_scan_duration_seconds_bucket[5m])) > 2
```

---

## HTTP-instrumentering (prometheus-fastapi-instrumentator)

Dessa metrics genereras automatiskt av
[prometheus-fastapi-instrumentator](https://github.com/trallnag/prometheus-fastapi-instrumentator)
för alla HTTP-endpoints **utom** `/metrics` och `/health`.

### `http_requests_total`

| Egenskap | Värde |
|----------|-------|
| Typ | Counter |
| Labels | `method`, `handler`, `status_code` |

```promql
# Request-rate per endpoint
rate(http_requests_total[5m])

# Felfrekvens (4xx + 5xx)
sum(rate(http_requests_total{status_code=~"[45].."}[5m]))
  / sum(rate(http_requests_total[5m])) * 100

# 429-rate (rate limit-träffar)
rate(http_requests_total{status_code="429"}[5m])
```

### `http_request_duration_seconds`

| Egenskap | Värde |
|----------|-------|
| Typ | Histogram |
| Labels | `method`, `handler`, `status_code` |

```promql
# p95 svarstid för /upload
histogram_quantile(0.95,
  rate(http_request_duration_seconds_bucket{handler="/upload"}[5m])
)

# Genomsnittlig svarstid per endpoint
rate(http_request_duration_seconds_sum[5m])
  / rate(http_request_duration_seconds_count[5m])
```

---

## Rekommenderade Alertmanager-regler

```yaml
groups:
  - name: sentinel
    rules:

      # Hög avvisningsfrekvens — möjlig attack eller felkonfiguration
      - alert: HighRejectionRate
        expr: |
          sum(rate(sentinel_uploads_total{status="rejected"}[5m]))
            / sum(rate(sentinel_uploads_total[5m])) > 0.3
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Mer än 30% av uppladdningar avvisas"

      # Skanningsmotor nere — mock används i stället för ClamAV
      - alert: MockScannerInUse
        expr: |
          sum(rate(sentinel_uploads_total{engine="mock"}[5m])) > 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "ClamAV ej tillgänglig — mock-skanner används"

      # Långsam skanning — ClamAV-problem eller resurspress
      - alert: SlowScanDuration
        expr: |
          histogram_quantile(0.95,
            rate(sentinel_scan_duration_seconds_bucket[5m])
          ) > 2
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "p95 skanntid överstiger 2 sekunder"

      # Hög HTTP-felfrekvens
      - alert: HighErrorRate
        expr: |
          sum(rate(http_requests_total{status_code=~"5.."}[5m]))
            / sum(rate(http_requests_total[5m])) > 0.05
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Mer än 5% av requests returnerar 5xx"
```

---

## Kubernetes scrape-konfiguration

För Prometheus Operator, lägg till dessa annotationer på Sentinel-podden:

```yaml
# k8s/base/deployment.yaml  (under spec.template.metadata.annotations)
annotations:
  prometheus.io/scrape: "true"
  prometheus.io/port: "8000"
  prometheus.io/path: "/metrics"
```

Eller skapa en `ServiceMonitor` om du använder Prometheus Operator:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: sentinel
  namespace: monitoring
spec:
  selector:
    matchLabels:
      app: sentinel-upload-api
  endpoints:
    - port: http
      path: /metrics
      interval: 15s
```

---

## Intern summerings-endpoint

Utöver `/metrics` finns `GET /metrics/summary` som returnerar JSON med aggregerade
statistik från MongoDB (senaste 24h, 7 dagar, all-time). Denna endpoint är inte
Prometheus-kompatibel och är avsedd för dashboards och direktanvändning.

```bash
curl http://localhost:8000/metrics/summary
```

```json
{
  "last_24h":  { "total_uploads": 42, "accepted": 38, "rejected": 3, "review": 1,
                 "deduplicated": 5, "avg_risk_score": 14.2, "rejection_rate_percent": 7.1 },
  "last_7d":   { ... },
  "all_time":  { ... },
  "top_content_types_7d": [
    { "content_type": "text/plain", "count": 18 },
    { "content_type": "application/pdf", "count": 12 }
  ]
}
```
