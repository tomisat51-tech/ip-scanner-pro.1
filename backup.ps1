# backup.ps1
# Pelny backup serwera na dysk D:
# Uruchom recznie lub dodaj do Task Scheduler (np. codziennie o 3:00)

$ErrorActionPreference = "Continue"

$date       = Get-Date -Format "yyyy-MM-dd_HH-mm"
$backupRoot = "D:\ServerBackup"
$backupDir  = "$backupRoot\$date"
$logFile    = "$backupRoot\backup.log"

function Log($msg) {
    $line = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $msg"
    Write-Host $line
    Add-Content $logFile $line -Encoding UTF8
}

function Backup-Dir($src, $dst, $label) {
    if (-not (Test-Path $src)) { Log "POMINIĘTO (brak): $src"; return }
    New-Item -ItemType Directory -Path $dst -Force | Out-Null
    Log "Kopiuję $label..."
    $result = robocopy $src $dst /E /Z /MT:8 /R:2 /W:3 /NP /NFL /NDL 2>&1
    $exitCode = $LASTEXITCODE
    if ($exitCode -le 7) {
        Log "OK: $label (robocopy kod $exitCode)"
    } else {
        Log "BLAD: $label (robocopy kod $exitCode)"
    }
}

# Sprawdz dysk D:
if (-not (Test-Path "D:\")) {
    Write-Host "BLAD: Dysk D: nie istnieje lub jest niedostepny!" -ForegroundColor Red
    exit 1
}

# Sprawdz wolne miejsce na D:
$dFree = (Get-PSDrive D).Free / 1GB
Log "Wolne miejsce na D: $([math]::Round($dFree, 1)) GB"
if ($dFree -lt 2) {
    Log "UWAGA: Mniej niz 2GB wolnego miejsca na D:!"
}

New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
Log "=== BACKUP START: $backupDir ==="

# --- go2rtc ---
$go2rtcProc = Get-Process -Name "go2rtc" -ErrorAction SilentlyContinue
if ($go2rtcProc) {
    $go2rtcDir = Split-Path $go2rtcProc.Path
    Backup-Dir $go2rtcDir "$backupDir\go2rtc" "go2rtc"
}

# Szukaj config go2rtc
$go2rtcConfigs = @(
    "$env:APPDATA\go2rtc",
    "$env:LOCALAPPDATA\go2rtc",
    "C:\go2rtc",
    "C:\Program Files\go2rtc"
)
foreach ($cfg in $go2rtcConfigs) {
    if (Test-Path "$cfg\go2rtc.yaml") {
        Backup-Dir $cfg "$backupDir\go2rtc_config" "go2rtc config"
        break
    }
}

# --- Claude Agent ---
$agentDir = "C:\Users\$env:USERNAME\claude-agent"
Backup-Dir $agentDir "$backupDir\claude-agent" "claude-agent"

# --- Node.js apps (wykryj z procesow) ---
$nodeProcs = Get-WmiObject Win32_Process -Filter "name='node.exe'" -ErrorAction SilentlyContinue
$backedDirs = @{}
foreach ($proc in $nodeProcs) {
    if ($proc.CommandLine -match '"([A-Z]:\\[^"]+)\\src\\server\.js"') {
        $dir = Split-Path $Matches[1]
        if (-not $backedDirs[$dir]) {
            Backup-Dir $dir "$backupDir\node_server" "Node.js server"
            $backedDirs[$dir] = $true
        }
    }
}

# --- Python apps ---
$pyProcs = @()
$pyProcs += Get-WmiObject Win32_Process -Filter "name='pythonw.exe'" -ErrorAction SilentlyContinue
$pyProcs += Get-WmiObject Win32_Process -Filter "name='python.exe'"  -ErrorAction SilentlyContinue
$pyIdx = 1
foreach ($proc in $pyProcs) {
    if ($proc.CommandLine -match '"([A-Z]:\\[^"]+\.py)"') {
        $dir = Split-Path $Matches[1]
        if (-not $backedDirs[$dir]) {
            Backup-Dir $dir "$backupDir\python_app$pyIdx" "Python app $pyIdx"
            $backedDirs[$dir] = $true
            $pyIdx++
        }
    }
}

# --- Task Scheduler eksport (konfiguracja autostart) ---
Log "Eksportuje Task Scheduler..."
$tsDir = "$backupDir\task_scheduler"
New-Item -ItemType Directory -Path $tsDir -Force | Out-Null
foreach ($task in @("go2rtc","ClaudeAgent","NodeServer5055","ServerWatchdog","PythonApp1","PythonApp2")) {
    try {
        schtasks /query /tn $task /xml > "$tsDir\$task.xml" 2>$null
    } catch {}
}

# --- Usun stare backupy (zachowaj ostatnie 7) ---
Log "Czyszczenie starych backupow..."
$allBackups = Get-ChildItem $backupRoot -Directory | Sort-Object Name -Descending
if ($allBackups.Count -gt 7) {
    $allBackups | Select-Object -Skip 7 | ForEach-Object {
        Remove-Item $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
        Log "Usunieto stary backup: $($_.Name)"
    }
}

# --- Podsumowanie ---
$size = (Get-ChildItem $backupDir -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1MB
Log "=== BACKUP ZAKOŃCZONY: $([math]::Round($size,1)) MB w $backupDir ==="
Write-Host ""
Write-Host "Backup gotowy: $backupDir" -ForegroundColor Green
Write-Host "Rozmiar: $([math]::Round($size,1)) MB" -ForegroundColor Cyan
