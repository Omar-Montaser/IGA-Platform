# Configure this PowerShell session only. No credentials are written to disk.
[CmdletBinding()]
param(
    [ValidateSet('gemini', 'groq')][string]$Provider = 'gemini',
    [string]$Python
)
$ErrorActionPreference = 'Stop'
$Provider = $Provider.ToLowerInvariant()
if (-not $Python) {
    $Python = Join-Path $PSScriptRoot '.venv-ai\Scripts\python.exe'
    if (-not (Test-Path -LiteralPath $Python)) { $Python = Join-Path $PSScriptRoot '.venv\Scripts\python.exe' }
}
& $Python -c 'import iga_review.cli'
if ($LASTEXITCODE -ne 0) { throw 'Install Module 4 into a working Python environment first (see README).' }
Write-Host 'Use a free-tier project without billing. The application cannot verify billing status.'
Write-Host 'Use synthetic data only; review the selected provider data-use terms before sending sensitive evidence.'
$keyVariable = if ($Provider -eq 'groq') { 'GROQ_API_KEY' } else { 'GEMINI_API_KEY' }
if (-not [Environment]::GetEnvironmentVariable($keyVariable, 'Process')) {
    $secureKey = Read-Host "$Provider API key (not saved to disk)" -AsSecureString
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureKey)
    try { [Environment]::SetEnvironmentVariable($keyVariable, [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer), 'Process') }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer); $secureKey.Dispose() }
}
$env:IGA_AI_PROVIDER = $Provider
$env:IGA_AI_MODEL = if ($Provider -eq 'groq') { 'llama-3.3-70b-versatile' } else { 'gemini-3.8-flash' }
& $Python -m iga_review.cli ai-check
if ($LASTEXITCODE -ne 0) { throw 'AI inference was not verified. Resolve the reported failure; review history was not changed.' }
Write-Host 'AI structured response verified. Use the SAME PowerShell session.'
Write-Host "From '$PSScriptRoot', start a new synthetic campaign:"
Write-Host "& '$Python' -m iga_review.cli demo --state-dir .demo-review/$Provider"
Write-Host 'An existing directory preserves existing assessments. Choose a new child directory for a fresh demo.'
