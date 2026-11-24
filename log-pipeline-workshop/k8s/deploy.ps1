# Deploy the secure log pipeline to the current local Kubernetes context.
# Prerequisites: a local cluster (Docker Desktop -> Settings -> Kubernetes -> Enable), and the
# images built once with:  docker compose -f log-pipeline-workshop/docker-compose.yml --profile pipeline build
# Uses the same config files and .env as the Docker Compose version. Never prints secrets.
$ErrorActionPreference = 'Stop'
$lab = Split-Path -Parent $PSScriptRoot
$ns = 'log-pipeline'

kubectl create namespace $ns --dry-run=client -o yaml | kubectl apply -f -

kubectl -n $ns create configmap fluent-bit-config --dry-run=client -o yaml `
    --from-file="$lab/fluent-bit/fluent-bit.conf" --from-file="$lab/fluent-bit/parsers.conf" `
    --from-file="$lab/fluent-bit/sanitise.lua" | kubectl apply -f -
kubectl -n $ns create configmap loki-config --dry-run=client -o yaml `
    --from-file="$lab/loki/loki-standard.yaml" --from-file="$lab/loki/loki-forensic.yaml" | kubectl apply -f -
kubectl -n $ns create configmap grafana-provisioning --dry-run=client -o yaml `
    --from-file="dashboards.yaml=$lab/grafana/dashboards.yaml" `
    --from-file="standard-datasources.yaml=$lab/grafana/standard/datasources.yaml" `
    --from-file="forensic-datasources.yaml=$lab/grafana/forensic/datasources.yaml" `
    --from-file="standard-logs.json=$lab/grafana/standard/logs.json" `
    --from-file="forensic-logs.json=$lab/grafana/forensic/logs.json" | kubectl apply -f -
kubectl -n $ns create secret generic grafana-admin --dry-run=client -o yaml `
    --from-env-file="$lab/.env" | kubectl apply -f - | Out-Null

kubectl apply -f (Join-Path $PSScriptRoot 'log-pipeline.yaml')
kubectl -n $ns rollout status deployment/log-presidio --timeout=300s
kubectl -n $ns get pods

Write-Host "`nOpen the dashboards (each in its own terminal):"
Write-Host "  kubectl -n $ns port-forward deployment/grafana 3100:3000            -> http://127.0.0.1:3100"
Write-Host "  kubectl -n $ns port-forward deployment/grafana-forensic 3101:3000   -> http://127.0.0.1:3101"
Write-Host "Remove everything:  kubectl delete namespace $ns"
