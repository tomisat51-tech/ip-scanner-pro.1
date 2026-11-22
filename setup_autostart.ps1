# setup_autostart.ps1
# Uruchom jako Administrator: Right-click -> "Uruchom jako administrator"
# Wykrywa aktywne uslugi i rejestruje je w Task Scheduler

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"
$logFile = "$PSScriptRoot\autostart_setup.log"

function Log($msg) {
    $line = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $msg"
    Write-Host $line
    Add-Content $logFile $line -Encoding UTF8
}

function Register-StartupTask {
    param($name, $exe, $taskArgs, $workDir, $delay = 30)

    $action  = New-ScheduledTaskAction -Execute $exe -Argument $taskArgs -WorkingDirectory $workDir
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $trigger.Delay = "PT${delay}S"
    $settings = New-ScheduledTaskSettingsSet `
        -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
        -ExecutionTimeLimit ([TimeSpan]::Zero) `
        -StartWhenAvailable -MultipleInstances IgnoreNew

    $principal = New-ScheduledTaskPrincipal `
        -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest

    Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue
    Register-ScheduledTask -TaskName $name -Action $action `
        -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
    Log "Zarejestrowano: $name  ($exe $args)"
}

Log "=== SETUP AUTOSTART START ==="

# --- Wykryj go2rtc ---
$go2rtcProc = Get-Process -Name "go2rtc" -ErrorAction SilentlyContinue
if ($go2rtcProc) {
    $go2rtcPath = $go2rtcProc.Path
    $go2rtcDir  = Split-Path $go2rtcPath
    Register-StartupTask "go2rtc" $go2rtcPath "" $go2rtcDir 10
    Log "go2rtc znaleziony: $go2rtcPath"
} else {
    # Szukaj na dysku
    $found = Get-ChildItem -Path "C:\" -Recurse -Filter "go2rtc.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) {
        Register-StartupTask "go2rtc" $found.FullName "" $found.DirectoryName 10
        Log "go2rtc znaleziony (wyszukiwanie): $($found.FullName)"
    } else {
        Log "UWAGA: go2rtc.exe nie znaleziony - dodaj recznie"
    }
}

# --- Wykryj node.js apps ---
$nodeProcs = Get-WmiObject Win32_Process -Filter "name='node.exe'" -ErrorAction SilentlyContinue
foreach ($proc in $nodeProcs) {
    $cmd = $proc.CommandLine
    if ($cmd -match 'claude-agent\\agent\.js') {
        $agentPath = "C:\Users\$env:USERNAME\claude-agent\agent.js"
        $agentDir  = "C:\Users\$env:USERNAME\claude-agent"
        Register-StartupTask "ClaudeAgent" "node.exe" "`"$agentPath`"" $agentDir 45
    }
    elseif ($cmd -match 'src\\server\.js') {
        # Wykryj katalog roboczy
        $wdir = $proc.CommandLine -replace '".*?node\.exe"\s+', ''
        $wdir = Split-Path ($wdir -replace '"', '')
        if (-not (Test-Path $wdir)) { $wdir = "C:\Users\$env:USERNAME" }
        Register-StartupTask "NodeServer5055" "node.exe" "src\server.js" $wdir 40
    }
}

# --- Wykryj Python apps ---
$pyProcs = @()
$pyProcs += Get-WmiObject Win32_Process -Filter "name='pythonw.exe'" -ErrorAction SilentlyContinue
$pyProcs += Get-WmiObject Win32_Process -Filter "name='python.exe'"  -ErrorAction SilentlyContinue

$pyIdx = 1
foreach ($proc in $pyProcs) {
    if ($proc.CommandLine -match '(?i)(pythonw?\.exe)"\s+"?([^\s"]+\.py)') {
        $script  = $Matches[2]
        $workDir = Split-Path $script
        $exe     = if ($proc.Name -eq "pythonw.exe") { "pythonw.exe" } else { "python.exe" }
        Register-StartupTask "PythonApp$pyIdx" $exe "`"$script`"" $workDir (50 + $pyIdx * 5)
        $pyIdx++
    }
}

# --- Zarejestruj Watchdog ---
$watchdogPath = "$PSScriptRoot\watchdog.ps1"
if (Test-Path $watchdogPath) {
    $wdAction = New-ScheduledTaskAction `
        -Execute "powershell.exe" `
        -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$watchdogPath`""
    $wdTrigger = New-ScheduledTaskTrigger -AtStartup
    $wdTrigger.Delay = "PT60S"
    $wdSettings = New-ScheduledTaskSettingsSet `
        -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable
    $wdPrincipal = New-ScheduledTaskPrincipal `
        -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest
    Unregister-ScheduledTask -TaskName "ServerWatchdog" -Confirm:$false -ErrorAction SilentlyContinue
    Register-ScheduledTask -TaskName "ServerWatchdog" -Action $wdAction `
        -Trigger $wdTrigger -Settings $wdSettings -Principal $wdPrincipal -Force | Out-Null
    Log "Watchdog zarejestrowany"
}

Log "=== SETUP ZAKOŃCZONY ==="
Write-Host ""
Write-Host "Gotowe! Zarejestrowane zadania w Task Scheduler:" -ForegroundColor Green
Get-ScheduledTask | Where-Object { $_.TaskName -in @("go2rtc","ClaudeAgent","NodeServer5055","ServerWatchdog") + (1..5 | ForEach-Object { "PythonApp$_" }) } |
    Select-Object TaskName, State | Format-Table -AutoSize
Write-Host ""
Write-Host "Restart komputera zeby przetestowac autostart." -ForegroundColor Yellow
