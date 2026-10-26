# Proves Phase AI CA rotation against a real current-user Root store on a
# Windows runner, where certutil raises no confirmation prompts.
param([Parameter(Mandatory = $true)][string]$Phase)
$ErrorActionPreference = 'Stop'
$Phase = (Resolve-Path $Phase).Path

function Invoke-Enable([string]$Label) {
  $output = & $Phase ai enable --harness claude-code --mask --trust-ca 2>&1 | Out-String
  Write-Host "--- $Label (exit $LASTEXITCODE)"
  Write-Host $output
  if ($LASTEXITCODE -ne 0) { throw "$Label failed" }
  return $output
}
function Get-PhaseRoots {
  Get-ChildItem Cert:\CurrentUser\Root | Where-Object { $_.Subject -match 'CN=Phase AI Proxy CA' }
}
function Get-LocalCAThumbprint {
  (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 "$env:USERPROFILE\.phase\ai\ca.pem").Thumbprint
}

$first = Invoke-Enable 'first enable'
if ($first -notmatch 'CA trusted in the Windows current-user Root store') { throw 'first enable did not trust the CA' }
$firstThumbprint = Get-LocalCAThumbprint
if (@(Get-PhaseRoots).Count -ne 1) { throw 'expected exactly one Phase root after the first enable' }

# Replace the CA: with ca.pem gone, Ensure generates a new one and the old
# root stays trusted, which is the rotation case.
Remove-Item "$env:USERPROFILE\.phase\ai\ca.pem"
$second = Invoke-Enable 'second enable (rotation)'
if ($second -notmatch 'CA trusted in the Windows current-user Root store') { throw 'rotation did not trust the new CA' }
$secondThumbprint = Get-LocalCAThumbprint
if ($secondThumbprint -eq $firstThumbprint) { throw 'the CA was not replaced' }
$roots = @(Get-PhaseRoots)
if ($roots.Count -ne 1 -or $roots[0].Thumbprint -ne $secondThumbprint) {
  throw "expected only the new root $secondThumbprint, found: $($roots | ForEach-Object Thumbprint)"
}

$third = Invoke-Enable 'third enable (idempotent)'
if ($third -notmatch 'already trusted') { throw 'third enable did not report the CA as already trusted' }

Write-Host 'OK: Windows CA rotation'
