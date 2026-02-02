# ToDo

- [ ] Add bug-report button in UI (link to GitHub Issues)
- [x] Add Trivy image scan in CI (fail on HIGH/CRITICAL)
- [ ] Add dependency scanning (pip-audit or Trivy fs)
- [x] Generate SBOM (Syft) and store as CI artifact
- [x] Switch base image to Alpine to reduce OS CVEs
- [ ] Add MongoDB storage for upload metadata
- [ ] Sign images with Cosign (bonus)
- [ ] Add Kubernetes manifests (Deployment, Service, Ingress)
- [ ] Gatekeeper policies: no :latest, non-root, resource limits, labels, readOnlyRootFilesystem
- [ ] Add Falco runtime rule and test alert
- [ ] Define SLIs/SLOs in metrics pipeline
- [ ] Set up monitoring (Prometheus/Grafana) and logging
- [ ] Write incident runbook for upload API unavailable
- [ ] Fill in shared responsibility model and cost notes
- [ ] Ändra Mongo port från 27017 till 28017 då 27017 är blockerad av HyperV

