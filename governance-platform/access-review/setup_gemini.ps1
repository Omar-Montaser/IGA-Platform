# Backward-compatible entry point for the earlier setup instructions.
param([string]$Python)
& (Join-Path $PSScriptRoot 'setup_ai.ps1') -Provider gemini -Python $Python
