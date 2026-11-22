# fix_cameras.ps1
# Diagnostyka i naprawa kamer w go2rtc
# Uruchom w PowerShell: .\fix_cameras.ps1

$ErrorActionPreference = "Continue"

Write-Host ""
Write-Host "=== DIAGNOSTYKA KAMER go2rtc ===" -ForegroundColor Cyan
Write-Host ""

# 1. Sprawdz czy go2rtc dziala
$proc = Get-Process -Name "go2rtc" -ErrorAction SilentlyContinue
if ($proc) {
    Write-Host "[OK] go2rtc dziala (PID: $($proc.Id))" -ForegroundColor Green
    $go2rtcDir = Split-Path $proc.Path
    Write-Host "     Lokalizacja: $($proc.Path)"
} else {
    Write-Host "[BLAD] go2rtc NIE dziala!" -ForegroundColor Red
    Write-Host "       Uruchom go2rtc i sprobuj ponownie."
    exit 1
}

# 2. Sprawdz panel go2rtc
Write-Host ""
Write-Host "Sprawdzam panel go2rtc na http://localhost:1984 ..."
try {
    $resp = Invoke-WebRequest -Uri "http://localhost:1984" -UseBasicParsing -TimeoutSec 3
    Write-Host "[OK] Panel go2rtc dostepny (HTTP $($resp.StatusCode))" -ForegroundColor Green
} catch {
    Write-Host "[BLAD] Panel go2rtc niedostepny: $_" -ForegroundColor Red
}

# 3. Znajdz plik konfiguracyjny
Write-Host ""
Write-Host "Szukam pliku konfiguracyjnego go2rtc.yaml ..."
$configPaths = @(
    "$go2rtcDir\go2rtc.yaml",
    "$go2rtcDir\go2rtc.yml",
    "$env:APPDATA\go2rtc\go2rtc.yaml",
    "$env:LOCALAPPDATA\go2rtc\go2rtc.yaml",
    "C:\go2rtc\go2rtc.yaml",
    "$env:USERPROFILE\go2rtc.yaml"
)

$configFile = $null
foreach ($p in $configPaths) {
    if (Test-Path $p) {
        $configFile = $p
        Write-Host "[OK] Znaleziono config: $p" -ForegroundColor Green
        break
    }
}

if (-not $configFile) {
    Write-Host "[UWAGA] Brak pliku go2rtc.yaml - tworze szablon..." -ForegroundColor Yellow
    $configFile = "$go2rtcDir\go2rtc.yaml"
}

# 4. Pokaz aktualny config
Write-Host ""
Write-Host "--- Aktualny config ($configFile) ---" -ForegroundColor Yellow
if (Test-Path $configFile) {
    Get-Content $configFile
} else {
    Write-Host "(plik nie istnieje)"
}

# 5. Sprawdz API - jakie strumienie sa skonfigurowane
Write-Host ""
Write-Host "Sprawdzam aktywne strumienie przez API..."
try {
    $streams = Invoke-RestMethod -Uri "http://localhost:1984/api/streams" -TimeoutSec 3
    if ($streams) {
        Write-Host "[OK] Skonfigurowane strumienie:" -ForegroundColor Green
        $streams | ConvertTo-Json -Depth 3
    } else {
        Write-Host "[UWAGA] Brak skonfigurowanych strumieni kamer!" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[INFO] Nie mozna pobrac listy strumieni" -ForegroundColor Gray
}

# 6. Sprawdz polaczenia sieciowe go2rtc
Write-Host ""
Write-Host "Aktywne polaczenia go2rtc:"
netstat -ano | Select-String "$($proc.Id)" | Where-Object { $_ -notmatch "LISTENING" }

# 7. Pokaz instrukcje naprawy
Write-Host ""
Write-Host "=== JAK DODAC REJESTRATORY ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Otwórz plik: $configFile" -ForegroundColor White
Write-Host "i dodaj swoje rejestratory w formacie:"
Write-Host ""
Write-Host @"
streams:
  kamera1:
    - rtsp://admin:haslo@192.168.1.X:554/stream1
  kamera2:
    - rtsp://admin:haslo@192.168.1.X:554/stream2
  rejestrator1:
    - rtsp://admin:haslo@192.168.1.48:554/Streaming/Channels/101
  rejestrator2:
    - rtsp://admin:haslo@192.168.1.163:554/Streaming/Channels/101
"@ -ForegroundColor Gray

Write-Host ""
Write-Host "Typowe porty RTSP rejestratorow:" -ForegroundColor Yellow
Write-Host "  Hikvision:  rtsp://admin:haslo@IP:554/Streaming/Channels/101"
Write-Host "  Dahua:      rtsp://admin:haslo@IP:554/cam/realmonitor?channel=1&subtype=0"
Write-Host "  Reolink:    rtsp://admin:haslo@IP:554/h264Preview_01_main"
Write-Host "  ONVIF:      rtsp://admin:haslo@IP:554/onvif/profile1/media.smp"
Write-Host ""

# 8. Podaj adresy podejrzanych urzadzen z sieci
Write-Host "Podejrzane urzadzenia w Twojej sieci (moga byc rejestratorami):" -ForegroundColor Yellow
$arpOutput = arp -a | Select-String "192\.168\.1\.(48|163)"
$arpOutput | ForEach-Object { Write-Host "  $_" }
Write-Host "  -> Sprawdz 192.168.1.48 i 192.168.1.163 (ten sam producent: 00-12-33)"
Write-Host ""

# 9. Opcja: uruchom edytor konfiguracji
$edit = Read-Host "Czy chcesz otworzyc plik konfiguracyjny teraz? (t/n)"
if ($edit -eq "t") {
    if (-not (Test-Path $configFile)) {
        # Stworz domyslny config
        @"
api:
  listen: :1984

streams:
  # Dodaj swoje kamery/rejestratory tutaj
  # Przyklad:
  # kamera1:
  #   - rtsp://admin:haslo@192.168.1.48:554/Streaming/Channels/101
  # kamera2:
  #   - rtsp://admin:haslo@192.168.1.163:554/Streaming/Channels/101
"@ | Set-Content $configFile -Encoding UTF8
        Write-Host "Utworzono szablon: $configFile" -ForegroundColor Green
    }
    notepad $configFile
    Write-Host ""
    Write-Host "Po zapisaniu konfiguracji zrestartuj go2rtc:" -ForegroundColor Yellow
    Write-Host "  Stop-Process -Name go2rtc -Force"
    Write-Host "  Start-Process `"$($proc.Path)`" -WorkingDirectory `"$go2rtcDir`""
}

Write-Host ""
Write-Host "Panel go2rtc: http://localhost:1984" -ForegroundColor Cyan
Write-Host "Gotowe." -ForegroundColor Green
