# Security Policy

## Reporting a Vulnerability

Please report security issues privately.
Use GitHub Security Advisories or open a private issue in this repository.

## Supported Versions

Only the latest version on the main branch is supported.

## Scope

In scope:
- Sentinel Upload API code and container image
- CI/CD configuration in this repository

Out of scope:
- Third-party services and infrastructure outside this repository

## CI Security Checks

- Container image scanning with Trivy (fail on HIGH/CRITICAL)
- SBOM generation with Syft (SPDX JSON artifact)
- Base image hardened (Alpine)
