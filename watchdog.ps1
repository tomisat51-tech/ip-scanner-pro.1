# watchdog.ps1
# Monitoruje uslugi i restartuje je jesli padna.
# Uruchamiany automatycznie przez Task Scheduler po starcie systemu.

$logFile = "$PSScriptRoot\watchdog.log"
$maxLogMB = 5

function Log($msg) {
    $line = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $msg"
    Add-Content $logFile $line -Encoding UTF8
    # rotacja logu
    if ((Get-Item $logFile -ErrorAction SilentlyContinue).Length -gt ($maxLogMB * 1MB)) {
        Rename-Item $logFile "$logFile.old" -Force -ErrorAction SilentlyContinue
    }
}

function Get-NodeCmd($port) {
    $conn = netstat -ano | Select-String ":$port\s+.*LISTENING"
    if ($conn) {
        $pid_ = ($conn -split '\s+')[-1]
        try {
            $proc = Get-WmiObject Win32_Process -Filter "ProcessId=$pid_"
            return @{ pid = $pid_; cmd = $proc.CommandLine; wdir = $proc.WorkingDirectory }
        } catch { return $null }
    }
    return $null
}

# Konfiguracja uslug do monitorowania
# Format: @{ name; process; exe; args; workdir; port; delay }
$services = @(
    @{
        name    = "go2rtc"
        process = "go2rtc"
        task    = "go2rtc"
        port    = 1984
    },
    @{
        name    = "ClaudeAgent"
        process = "node"
        task    = "ClaudeAgent"
        port    = 7799
    },
    @{
        name    = "NodeServer"
        process = "node"
        task    = "NodeServer5055"
        port    = 5055
    },
    @{
        name    = "PythonApp"
        process = "pythonw"
        task    = "PythonApp1"
        port    = 5050
    }
)

Log "=== WATCHDOG START ==="

while ($true) {
    foreach ($svc in $services) {
        # Sprawdz czy port nasluchuje
        $listening = netstat -ano | Select-String ":$($svc.port)\s+.*LISTENING"

        if (-not $listening) {
            Log "BRAK: $($svc.name) (port $($svc.port)) - restartuje..."
            try {
                Start-ScheduledTask -TaskName $svc.task -ErrorAction Stop
                Log "RESTART: $($svc.name) uruchomiony przez Task Scheduler"
            } catch {
                Log "BLAD restart $($svc.name): $_"
            }
            Start-Sleep -Seconds 15
            # Sprawdz czy wstalo
            $check = netstat -ano | Select-String ":$($svc.port)\s+.*LISTENING"
            if ($check) {
                Log "OK: $($svc.name) dziala na porcie $($svc.port)"
            } else {
                Log "NIEUDANY RESTART: $($svc.name) nadal nie dziala"
            }
        }
    }
    Start-Sleep -Seconds 60
}
