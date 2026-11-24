# Runs a step snippet's "docker compose exec <service> python -c '...'" block unchanged.
# Windows PowerShell 5.1 strips the double quotes inside the quoted -c argument, so the
# Python code is read from the snippet file and piped into the container instead.
# Usage, from agent-security-workshop:  .\run-snippet.ps1 snippets\step-4-network-and-model.txt
param([Parameter(Mandatory)][string]$Snippet)
Set-Location $PSScriptRoot
$text = Get-Content -Raw -Encoding UTF8 $Snippet
$match = [regex]::Match($text, "docker compose exec (\S+) python -c '(?s)(.*)'")
if (-not $match.Success) { throw "no 'docker compose exec <service> python -c' block found in $Snippet" }
$service = $match.Groups[1].Value
Write-Host "Running $Snippet in service '$service'" -ForegroundColor Cyan
$match.Groups[2].Value -replace "`r", '' | docker compose exec -T $service python -
exit $LASTEXITCODE
