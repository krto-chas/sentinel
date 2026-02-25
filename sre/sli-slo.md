# SLI/SLO – Sentinel Upload API

## Service Level Indicators (SLI)

| SLI | Metric | Description |
|-----|--------|-------------|
| Upload Success Rate | `http_requests_total{handler="/upload"}` | % of POST /upload returning 2xx |
| Upload Latency p95 | `http_request_duration_seconds_bucket{handler="/upload"}` | 95th percentile response time |
| Scan Duration p95 | `sentinel_scan_duration_seconds_bucket` | 95th percentile file scan time |

## Service Level Objectives (SLO)

| SLO | Target | Window |
|-----|--------|--------|
| Upload Success Rate | ≥ 99.5% | 30 days |
| p95 Upload Latency | ≤ 500 ms | 30 days |

## Prometheus Queries

### SLO 1: Upload Success Rate
```promql
sum(rate(http_requests_total{handler="/upload", status=~"2.."}[30d]))
/
sum(rate(http_requests_total{handler="/upload"}[30d]))
* 100
```

### SLO 2: p95 Upload Latency (ms)
```promql
histogram_quantile(
  0.95,
  sum(rate(http_request_duration_seconds_bucket{handler="/upload"}[5m])) by (le)
) * 1000
```

### Upload Rate by Decision
```promql
sum(rate(sentinel_uploads_total[5m])) by (decision)
```

### Error Budget Remaining (%)
```promql
(
  sum(rate(http_requests_total{handler="/upload", status=~"2.."}[30d]))
  / sum(rate(http_requests_total{handler="/upload"}[30d]))
  - 0.995
) / (1 - 0.995) * 100
```

## Measurement

- Metrics exposed at `GET /metrics` (Prometheus text format)
- Scraped by Prometheus every 15 s (`docker/prometheus/prometheus.yml`)
- Visualized in Grafana at `http://localhost:3000` (dashboard: *Sentinel Upload API – SLO Dashboard*)
- Instrumented via `prometheus-fastapi-instrumentator` (HTTP metrics) + `prometheus-client` (custom: `sentinel_uploads_total`, `sentinel_risk_score`, `sentinel_scan_duration_seconds`)

## NIST CSF Mapping

| NIST Function | Implementation |
|---------------|----------------|
| DETECT | Prometheus + Grafana alerts vid SLO-brott |
| RESPOND | Alert → Runbook: Upload API Unavailable |
| RECOVER | SLO error budget spårar återhämtning |
