# Architecture (High Level)

## Components

- FastAPI service with /health and /upload
- Static UI served from / (app/static)
- Container image based on Alpine for reduced OS CVEs
- MongoDB planned for upload metadata storage
- Docker image built in CI
- GitHub Actions CI: test and build
- Kubernetes deployment (planned)
- Security scanning and SBOM (planned)

## Flow

Developer -> GitHub PR -> CI (tests + build) -> Container registry -> Kubernetes

## Notes

- Security gates are enforced in CI and by policy in Kubernetes.
- Observability is provided via logs and metrics (planned).
