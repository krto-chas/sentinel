# Kubernetes on Hetzner (k3s) - Quick Runbook

This runbook prepares Sentinel Upload API to run on a Hetzner VPS with k3s.

## 1) Install k3s on the VPS

```bash
curl -sfL https://get.k3s.io | sh -
sudo kubectl get nodes
```

## 2) Prepare secrets before apply

In this repo:

```bash
cp k8s/base/secret.example.yaml k8s/base/secret.yaml
```

Edit `k8s/base/secret.yaml` and set:
- `MONGODB_URI` (Atlas URI)
- `FIREBASE_WEB_API_KEY`
- `FIREBASE_CREDENTIALS_JSON`

Do **not** commit `k8s/base/secret.yaml`.

## 3) Apply manifests

```bash
kubectl apply -k k8s/base
```

## 4) Verify

```bash
kubectl get pods -n sentinel
kubectl get svc -n sentinel
kubectl get ingress -n sentinel
```

Check app logs:

```bash
kubectl logs -n sentinel deployment/sentinel-upload-api
```

Check ClamAV logs:

```bash
kubectl logs -n sentinel deployment/clamav
```

## 5) DNS and TLS

- Point `api.example.com` to the VPS public IP.
- Replace `api.example.com` in `k8s/base/ingress.yaml`.
- Use an ingress controller + cert-manager for Let's Encrypt certificates.

## 6) Security notes

- Keep `AUTH_MODE=firebase` in ConfigMap.
- Keep secrets only in `Secret` or an external secret manager.
- Do not use `:latest` image tags for production rollout.
