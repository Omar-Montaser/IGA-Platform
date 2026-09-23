# IGA prototype - one environment for every tab.
#
# Dot-source it (note the leading dot and space), do not just run it:
#
#     . .\env.ps1
#
# Running it normally sets the variables in a child process that exits
# immediately, which looks like it did nothing.
#
# The service token is NOT stored here. Put the plaintext token in
# %USERPROFILE%\iga-runtime\token.txt, which lives outside the repository so it
# cannot be committed. Create it once:
#
#     "your-token-here" | Out-File -Encoding ascii -NoNewline $env:USERPROFILE\iga-runtime\token.txt

$runtime = Join-Path $env:USERPROFILE 'iga-runtime'
$tokenFile = Join-Path $runtime 'token.txt'

if (-not (Test-Path $tokenFile)) {
    Write-Host "No service token found at $tokenFile" -ForegroundColor Red
    Write-Host 'Create it with the connector''s plaintext token, then dot-source this again.'
    return
}
$token = (Get-Content $tokenFile -Raw).Trim()
if (-not $token) { Write-Host "$tokenFile is empty." -ForegroundColor Red; return }

# --- Module 3: the connector, reaching the VM over SSH ---------------------
$env:IGA_TRANSPORT        = 'ssh'
$env:IGA_SSH_HOST         = '127.0.0.1'
$env:IGA_SSH_PORT         = '2222'
$env:IGA_SSH_USER         = 'iga_svc'
$env:IGA_SSH_KEY          = Join-Path $env:USERPROFILE '.ssh\iga_connector'
$env:IGA_SSH_KNOWN_HOSTS  = Join-Path $env:USERPROFILE '.ssh\known_hosts'
$env:IGA_MAPPING          = Join-Path $runtime 'entitlement_map.json'
$env:IGA_STATE            = Join-Path $runtime 'state.db'
$env:IGA_SOURCE           = 'linux-lab'
# The connector stores only the hash; the plaintext never reaches it.
$env:IGA_TOKEN_SHA256     = python -c "import hashlib,sys; print(hashlib.sha256(sys.argv[1].encode()).hexdigest())" $token

# --- Module 4: the review platform -----------------------------------------
$reviewState = Join-Path $PSScriptRoot '..\..\governance-platform\access-review\.live-review'
$env:IGA_LINUX_LAB_TOKEN  = $token
$env:IGA_AI_PROVIDER      = 'rules'      # no external AI; deterministic rules only

# --- import_campaign.py / measure_accuracy.py ------------------------------
$env:IGA_CONNECTOR_TOKEN  = $token
$env:IGA_REVIEW_STATE     = (Resolve-Path $reviewState -ErrorAction SilentlyContinue).Path
$env:IGA_GROUND_TRUTH     = Join-Path $runtime 'ground_truth.json'

# The answer key must stay off the Module 4 team's machines until measurement,
# or the accuracy number proves nothing.
Write-Host "IGA environment set."
Write-Host "  target      ssh://$($env:IGA_SSH_USER)@$($env:IGA_SSH_HOST):$($env:IGA_SSH_PORT)"
Write-Host "  mapping     $($env:IGA_MAPPING)"
Write-Host "  review dir  $($env:IGA_REVIEW_STATE)"
if (-not (Test-Path $env:IGA_GROUND_TRUTH)) {
    Write-Host "  answer key  NOT PRESENT at $($env:IGA_GROUND_TRUTH)" -ForegroundColor Yellow
} else {
    Write-Host "  answer key  $($env:IGA_GROUND_TRUTH)"
}
