param(
    [string]$StateDir = '.demo-review/presentation',
    [ValidateRange(1024, 65535)][int]$Port = 8043,
    [string]$Python = ''
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $Python) {
    $Python = Join-Path $repoRoot 'governance-platform/access-review/.venv-ai/Scripts/python.exe'
}
if (-not (Test-Path -LiteralPath $Python)) {
    throw 'Python environment not found. Follow the README setup steps or pass -Python with an installed interpreter.'
}

$previousProvider = $env:IGA_AI_PROVIDER
Push-Location -LiteralPath $repoRoot
try {
    # This entry point always runs the simulated source with offline rules.
    $env:IGA_AI_PROVIDER = 'rules'
    & $Python -m iga_review.cli demo --empty --state-dir $StateDir `
        --identities 'governance-platform/hr-policy/data/identities.json' `
        --policies 'governance-platform/hr-policy/data/policies.json' --port $Port
    if ($LASTEXITCODE -ne 0) { throw "Demo exited with code $LASTEXITCODE." }
} finally {
    $env:IGA_AI_PROVIDER = $previousProvider
    Pop-Location
}
