# One-command local demo (Windows PowerShell, no Docker): .\scripts\dev.ps1
$bytes = New-Object byte[] 32; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$env:BAYORA_AUTH_SECRET = ($bytes | ForEach-Object { $_.ToString("x2") }) -join ""
$env:BAYORA_RED_WORKER_TOKEN = "red-demo-credential-0001"
$env:BAYORA_BLUE_WORKER_TOKEN = "blue-demo-credential-001"
$env:BAYORA_EVALUATOR_TOKEN = "eval-demo-credential-0001"
$env:BAYORA_DEV_HEADER_AUTH = "1"; $env:BAYORA_SEED_DEMO = "1"
if (-not (Test-Path node_modules)) { npm install }
npm run dev
