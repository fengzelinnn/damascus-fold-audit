$ErrorActionPreference = 'Stop'
Push-Location (Join-Path $PSScriptRoot '..')
try {
    py -3.12 -c 'import sys; assert sys.version_info[:2] == (3,12)'
    if ($LASTEXITCODE -ne 0) { throw 'CPython 3.12 required' }
    $DamascusRunDir = 'runs/local-' + (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ') + '-' + $PID
    py -3.12 -m damascus_a preflight --output "$DamascusRunDir/preflight.json"
    if ($LASTEXITCODE -ne 0) { throw 'Preflight failed' }
    py -3.12 -m damascus_a correctness --d 2 --k 2 --cases 4 --backend cpu-reference --output "$DamascusRunDir/correctness"
    if ($LASTEXITCODE -ne 0) { throw 'Correctness checks failed' }
} finally { Pop-Location }
