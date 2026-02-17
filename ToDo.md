# ToDo

- [ ] Add bug-report button in UI (link to GitHub Issues)
- [x] Add Trivy image scan in CI (fail on HIGH/CRITICAL)
- [x] Add dependency scanning (pip-audit or Trivy fs)
- [x] Generate SBOM (Syft) and store as CI artifact
- [x] Switch base image to Alpine to reduce OS CVEs
- [x] Add MongoDB storage for upload metadata
- [x] Add file-scanning for malicious code to uploaded files (mock scanner)
- [x] Integrate ClamAV scanner service (auto mode with mock fallback)
- [x] Enforce fail-closed policy when scanner is unavailable
- [ ] Sign images with Cosign (bonus)
- [x] Add Kubernetes manifests (Deployment, Service, Ingress)
- [x] Gatekeeper policies: no :latest, non-root, resource limits, labels, readOnlyRootFilesystem
- [ ] Add Falco runtime rule and test alert
- [ ] Define SLIs/SLOs in metrics pipeline
- [ ] Set up monitoring (Prometheus/Grafana) and logging
- [ ] Write incident runbook for upload API unavailable
- [ ] Fill in shared responsibility model and cost notes
- [x] Change Mongo port fom 27017 to 28017 since 27017 is blocked by HyperV
- [ ] Add Firebase Auth + FastAPI tokencheck

