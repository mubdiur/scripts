# ============================================================
# ROUTER / INTERNET BANDWIDTH STRESS TEST v4
# ============================================================

# --- VERIFIED WORKING URLS ---
$downloadUrls = @(
    "https://speedtest.tele2.net/1GB.zip",
    "https://speedtest.tele2.net/100MB.zip",
    "https://speedtest.tele2.net/10MB.zip",
    "https://speedtest.newark.linode.com/100MB-newark.bin",
    "https://speedtest.dallas.linode.com/100MB-dallas.bin",
    "https://speedtest.fremont.linode.com/100MB-fremont.bin",
    "https://proof.ovh.net/files/1Gb.dat",
    "https://proof.ovh.net/files/100Mb.dat",
    "https://ash-speed.hetzner.com/1GB.bin",
    "https://ash-speed.hetzner.com/100MB.bin"
)

# Public Linux ISO torrents (free/legal)
$torrentMagnets = @(
    "magnet:?xt=urn:btih:3a6b8cc61bc16cf5df4a5e40a32e15261b83ae71&dn=ubuntu-24.04.2-desktop-amd64.iso&tr=https%3A%2F%2Ftorrent.ubuntu.com%2Fannounce",
    "magnet:?xt=urn:btih:b56b71d3a99d2d040f8c3bab34cf1ee64cce60bf&dn=debian-12.10.0-amd64-netinst.iso",
    "magnet:?xt=urn:btih:02767af55b9c5e7c4c0c3dcc2e84c0e6c9c2e5aa&dn=Fedora-Workstation-Live-x86_64-40.iso"
)

$pingTarget  = "8.8.8.8"
$logFile     = "stress_log.txt"
$intervalSec = 3

$downloadWorkers = [math]::Max(4, [math]::Min(24, [Environment]::ProcessorCount * 2))

$qbtUri  = "http://localhost:8080"
$qbtUser = "admin"
$qbtPass = "adminadmin"

# Real browser User-Agent — prevents CDN 403 blocks
$userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

# ============================================================
# SHARED STATE
# ============================================================
$shared = [hashtable]::Synchronized(@{
    Stop   = $false
    Bytes  = [System.Collections.Concurrent.ConcurrentDictionary[int,long]]::new()
    Errors = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
})

# ============================================================
# LOGGING
# ============================================================
function Log($msg, $color = "White") {
    $line = "[$(Get-Date -Format 'HH:mm:ss')] $msg"
    Write-Host $line -ForegroundColor $color
    Add-Content -Path $logFile -Value $line
}

# ============================================================
# DOWNLOAD WORKER — streams bytes, no disk writes
# ============================================================
$workerScript = {
    param([int]$workerId, [string[]]$urls, [hashtable]$shared, [string]$ua)

    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add("User-Agent", $ua)
    $wc.Headers.Add("Accept", "*/*")

    $buf = New-Object byte[] (512 * 1024)   # 512 KB read buffer

    while (-not $shared.Stop) {
        $url = $urls[(Get-Random -Maximum $urls.Length)]
        try {
            $stream = $wc.OpenRead($url)
            while (-not $shared.Stop) {
                $read = $stream.Read($buf, 0, $buf.Length)
                if ($read -le 0) { break }
                $shared.Bytes.AddOrUpdate(
                    $workerId,
                    [long]$read,
                    [Func[int,long,long]]{ param($k, $v) $v + $read }
                ) | Out-Null
            }
            $stream.Close()
        } catch {
            $shared.Errors.Enqueue("W$workerId : $($_.Exception.Message)")
            Start-Sleep -Milliseconds 1000
        }
    }
    $wc.Dispose()
}

# ============================================================
# PING MONITOR
# ============================================================
$pingScript = {
    param([string]$target, [hashtable]$shared, [string]$logFile)
    while (-not $shared.Stop) {
        try {
            $r   = Test-Connection -ComputerName $target -Count 1 -ErrorAction Stop
            $ms  = $r.ResponseTime
            $col = if ($ms -lt 20) { "Green" } elseif ($ms -lt 80) { "Yellow" } else { "Red" }
            $line = "[$(Get-Date -Format 'HH:mm:ss')] Latency: ${ms}ms"
        } catch {
            $col  = "Red"
            $line = "[$(Get-Date -Format 'HH:mm:ss')] Latency: FAIL"
        }
        Write-Host $line -ForegroundColor $col
        Add-Content -Path $logFile -Value $line
        Start-Sleep -Seconds 5
    }
}

# ============================================================
# QBITTORRENT
# ============================================================
function Start-TorrentFlood {
    param([string]$Uri, [string]$User, [string]$Pass, [string[]]$Magnets)
    try {
        $sess = New-Object Microsoft.PowerShell.Commands.WebRequestSession
        $r = Invoke-WebRequest -Uri "$Uri/api/v2/auth/login" -Method POST `
               -Body "username=$User&password=$Pass" -WebSession $sess -UseBasicParsing -TimeoutSec 3
        if ($r.Content -ne "Ok.") { throw "bad credentials" }
        foreach ($m in $Magnets) {
            $body = "urls=" + [Uri]::EscapeDataString($m) + "&savepath=nul&category=stress_test"
            Invoke-WebRequest -Uri "$Uri/api/v2/torrents/add" -Method POST `
                -Body $body -WebSession $sess -UseBasicParsing | Out-Null
        }
        Log "qBittorrent: added $($Magnets.Count) torrents." "Cyan"
        return $true
    } catch {
        Log "qBittorrent not available — HTTP-only mode." "Yellow"
        return $false
    }
}

function Stop-TorrentFlood {
    param([string]$Uri, [string]$User, [string]$Pass)
    try {
        $sess = New-Object Microsoft.PowerShell.Commands.WebRequestSession
        Invoke-WebRequest -Uri "$Uri/api/v2/auth/login" -Method POST `
            -Body "username=$User&password=$Pass" -WebSession $sess -UseBasicParsing | Out-Null
        $list = Invoke-WebRequest -Uri "$Uri/api/v2/torrents/info?category=stress_test" `
            -WebSession $sess -UseBasicParsing | ConvertFrom-Json
        if ($list.Count -gt 0) {
            $hashes = ($list | ForEach-Object { $_.hash }) -join "|"
            Invoke-WebRequest -Uri "$Uri/api/v2/torrents/delete" -Method POST `
                -Body "hashes=$hashes&deleteFiles=true" -WebSession $sess -UseBasicParsing | Out-Null
            Log "qBittorrent: cleaned up $($list.Count) torrent(s)." "Cyan"
        }
    } catch {}
}

# ============================================================
# PRE-FLIGHT: verify at least one URL works before launching
# ============================================================
Log "Auto-tuned: $downloadWorkers workers | $([Environment]::ProcessorCount) logical cores" "Cyan"
Log "Running pre-flight check..." "Yellow"

$workingUrls = [System.Collections.Generic.List[string]]::new()
foreach ($url in $downloadUrls) {
    try {
        $t = New-Object System.Net.WebClient
        $t.Headers.Add("User-Agent", $userAgent)
        $s = $t.OpenRead($url)
        $b = New-Object byte[] 4096
        $n = $s.Read($b, 0, $b.Length)
        $s.Close(); $t.Dispose()
        if ($n -gt 0) {
            $workingUrls.Add($url)
            Log "  OK: $url" "Green"
        }
    } catch {
        Log "  SKIP: $url ($($_.Exception.Message -replace "`n",' '))" "DarkYellow"
    }
}

if ($workingUrls.Count -eq 0) {
    Log "All URLs failed pre-flight. Check your internet/firewall." "Red"
    exit 1
}

Log "$($workingUrls.Count)/$($downloadUrls.Count) URLs reachable. Starting workers." "Green"
$downloadUrls = $workingUrls.ToArray()

# ============================================================
# LAUNCH RUNSPACE POOL
# ============================================================
$pool = [RunspaceFactory]::CreateRunspacePool(1, ($downloadWorkers + 4))
$pool.Open()
$runspaces = [System.Collections.Generic.List[hashtable]]::new()

for ($i = 0; $i -lt $downloadWorkers; $i++) {
    $ps = [PowerShell]::Create()
    $ps.RunspacePool = $pool
    [void]$ps.AddScript($workerScript)
    [void]$ps.AddArgument($i)
    [void]$ps.AddArgument($downloadUrls)
    [void]$ps.AddArgument($shared)
    [void]$ps.AddArgument($userAgent)
    $runspaces.Add(@{ PS = $ps; Handle = $ps.BeginInvoke() })
}

$pingPS = [PowerShell]::Create()
$pingPS.RunspacePool = $pool
[void]$pingPS.AddScript($pingScript)
[void]$pingPS.AddArgument($pingTarget)
[void]$pingPS.AddArgument($shared)
[void]$pingPS.AddArgument($logFile)
$pingHandle = $pingPS.BeginInvoke()

$torrentActive = Start-TorrentFlood -Uri $qbtUri -User $qbtUser -Pass $qbtPass -Magnets $torrentMagnets

Log "All workers live. Press Ctrl+C to stop." "Green"
Write-Host ""

# ============================================================
# MONITOR LOOP
# ============================================================
$startTime = Get-Date
$lastBytes = 0L
$peakMbps  = 0.0

try {
    while ($true) {
        Start-Sleep -Seconds $intervalSec

        # Drain errors (max 3 shown per interval to avoid spam)
        $errCount = 0; $errMsg = $null
        while ($shared.Errors.TryDequeue([ref]$errMsg)) {
            if ($errCount -lt 3) { Log "  ERR: $errMsg" "DarkRed" }
            $errCount++
        }
        if ($errCount -gt 3) { Log "  ... ($($errCount-3) more errors suppressed)" "DarkRed" }

        $totalNow = 0L
        foreach ($kv in $shared.Bytes.GetEnumerator()) { $totalNow += $kv.Value }

        $delta     = $totalNow - $lastBytes
        $lastBytes = $totalNow
        $mbps      = [math]::Round(($delta * 8) / ($intervalSec * 1MB), 2)
        $totalGB   = [math]::Round($totalNow / 1GB, 3)
        $elapsed   = [math]::Round(((Get-Date) - $startTime).TotalSeconds)
        if ($mbps -gt $peakMbps) { $peakMbps = $mbps }

        $color = if ($mbps -gt 50) { "Green" } elseif ($mbps -gt 2) { "Yellow" } else { "Red" }
        Log ("Speed: {0,8} Mbps  |  Peak: {1} Mbps  |  Downloaded: {2} GB  |  Elapsed: {3}s" `
            -f $mbps, $peakMbps, $totalGB, $elapsed) $color
    }
} finally {
    Log "Shutting down..." "Yellow"
    $shared.Stop = $true
    Start-Sleep -Seconds 2
    foreach ($r in $runspaces) { try { $r.PS.Stop(); $r.PS.Dispose() } catch {} }
    try { $pingPS.Stop(); $pingPS.Dispose() } catch {}
    $pool.Close(); $pool.Dispose()
    if ($torrentActive) { Stop-TorrentFlood -Uri $qbtUri -User $qbtUser -Pass $qbtPass }
    Log "Done. Peak: $peakMbps Mbps. Log: $logFile" "Cyan"
}