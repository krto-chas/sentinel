# Gatekeeper policies

This folder contains Gatekeeper policy definitions for:

- disallowing `:latest` (and implicit latest with no tag)
- requiring non-root runtime
- requiring CPU/memory requests and limits
- requiring standard workload labels
- requiring read-only root filesystem

## Apply order

1. Install Gatekeeper in your cluster.
2. Apply all files in `constrainttemplates`.
3. Apply all files in `constraints`.

Example:

```bash
kubectl apply -f k8s/gatekeeper/constrainttemplates/
kubectl apply -f k8s/gatekeeper/constraints/
```
