# Checks and inspects the agent container's isolation (step 3).
# Run from agent-security-workshop:  .\check-isolation.ps1
# Safe to run repeatedly; it only reads.
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

$id = docker compose ps -q agent
if (-not $id) { throw 'agent container is not running; start it with: docker compose up -d --wait' }
$c = (docker inspect $id | ConvertFrom-Json)[0]
$h = $c.HostConfig

Write-Host "`n== 1. Container settings" -ForegroundColor Cyan
[pscustomobject]@{
    User           = $c.Config.User
    Privileged     = $h.Privileged
    ReadOnlyRoot   = $h.ReadonlyRootfs
    CapDrop        = $h.CapDrop -join ','
    CapAdd         = if ($h.CapAdd) { $h.CapAdd -join ',' } else { '(none)' }
    SecurityOpt    = $h.SecurityOpt -join ','
    PidNamespace   = if ($h.PidMode) { $h.PidMode } else { 'private (default)' }
    IpcNamespace   = $h.IpcMode
    UtsNamespace   = if ($h.UTSMode) { $h.UTSMode } else { 'private (default)' }
    UserNamespace  = if ($h.UsernsMode) { $h.UsernsMode } else { 'default' }
    CgroupNs       = $h.CgroupnsMode
    Network        = $h.NetworkMode
} | Format-List

Write-Host '== 2. Mounts (everything the agent can see from outside its image)' -ForegroundColor Cyan
$c.Mounts | ForEach-Object { [pscustomobject]@{ Type = $_.Type; Destination = $_.Destination; Writable = $_.RW } } | Format-Table -AutoSize
$c.HostConfig.Tmpfs.PSObject.Properties | ForEach-Object { [pscustomobject]@{ Type = 'tmpfs'; Destination = $_.Name; Options = $_.Value } } | Format-Table -AutoSize

Write-Host '== 3. Inside the container' -ForegroundColor Cyan
# Piped on stdin: Windows PowerShell 5.1 strips the quotes inside a quoted argument.
@'
echo "id: $(id)"
echo "workspace contents: $(ls -A /workspace)"
grep -E '^(CapEff|NoNewPrivs)' /proc/self/status
for s in /var/run/docker.sock /run/docker.sock /run/host-services/docker.proxy.sock /run/host-services/ssh-auth.sock; do
  if [ -e "$s" ]; then echo "EXPOSED: $s"; else echo "absent:  $s"; fi
done
echo "SSH_AUTH_SOCK=${SSH_AUTH_SOCK:-(unset)}"
echo "processes visible: $(ls /proc | grep -c '^[0-9]')"
for f in /workspace/docker-compose.yml /workspace/Dockerfile /workspace/schema.sql; do
  if [ -r "$f" ]; then echo "READABLE: $f"; else echo "blocked: $f"; fi
done
exit 0
'@ -replace "`r", '' | ForEach-Object { "$_`n" } | docker compose exec -T agent sh

Write-Host "`n== 4. Step 3 check (snippets/step-3-isolation.txt)" -ForegroundColor Cyan
$snippet = Get-Content -Raw -Encoding UTF8 (Join-Path $PSScriptRoot 'snippets\step-3-isolation.txt')
$code = [regex]::Match($snippet, "python -c '(?s)(.*)'").Groups[1].Value
$code | docker compose exec -T agent python -
$step3 = $LASTEXITCODE

Write-Host "`n== 5. Isolation and hardening tests" -ForegroundColor Cyan
python -m pytest tests -q -p no:cacheprovider
$tests = $LASTEXITCODE

Write-Host ''
if ($step3 -eq 0 -and $tests -eq 0) { Write-Host 'RESULT: isolation checks passed' -ForegroundColor Green }
else { Write-Host 'RESULT: isolation checks FAILED' -ForegroundColor Red; exit 1 }
