# Bootstrap Windows (PowerShell):
#   irm https://raw.githubusercontent.com/DuPont9029/vanity-seed/main/run.ps1 | iex
# Con argomenti: scarica il file e lancia  .\run.ps1 --prefix C0DEAD
# Installa uv (che scarica Python e le dipendenze), aggiorna il codice
# dall'ultima versione su GitHub e avvia la ricerca.
$ErrorActionPreference = "Stop"
$Repo = "DuPont9029/vanity-seed"
$Branch = if ($env:VANITY_BRANCH) { $env:VANITY_BRANCH } else { "main" }
$Dir = if ($env:VANITY_DIR) { $env:VANITY_DIR } else { Join-Path $HOME "vanity-seed" }
New-Item -ItemType Directory -Force -Path $Dir | Out-Null
$env:Path = "$HOME\.local\bin;$env:Path"

if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    Write-Host ">> Installo uv..."
    powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
    $env:Path = "$HOME\.local\bin;$env:Path"
}

Write-Host ">> Aggiorno il codice da github.com/$Repo ($Branch)..."
$zip = Join-Path $env:TEMP "vanity-seed.zip"
$tmp = Join-Path $env:TEMP "vanity-seed-extract"
try {
    Invoke-WebRequest -UseBasicParsing "https://github.com/$Repo/archive/refs/heads/$Branch.zip" -OutFile $zip
    if (Test-Path $tmp) { Remove-Item $tmp -Recurse -Force }
    Expand-Archive -Path $zip -DestinationPath $tmp
    $src = Get-ChildItem $tmp -Directory | Select-Object -First 1
    $app = Join-Path $Dir "app"
    if (Test-Path $app) { Remove-Item $app -Recurse -Force }
    Move-Item $src.FullName $app
} catch {
    Write-Warning "Aggiornamento fallito, uso la copia locale ($_)"
    if (-not (Test-Path (Join-Path $Dir "app\vanity.py"))) { throw "Nessuna copia locale disponibile" }
}

Set-Location $Dir
uv run --script app\vanity.py @args
