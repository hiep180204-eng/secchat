param(
    [switch]$IncludeDestructive,
    [string]$ArtifactDir = "",
    [double]$DelaySeconds = 0.65,
    [switch]$NoMonitor
)

$ErrorActionPreference = "Stop"

$Repo = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $Repo

if (-not $ArtifactDir) {
    $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $ArtifactDir = Join-Path $Repo "tests\artifacts\visible_manual_checklist\$stamp"
}
New-Item -ItemType Directory -Force -Path $ArtifactDir | Out-Null

function Wait-HttpOk {
    param(
        [string]$Url,
        [int]$TimeoutSeconds = 90
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $last = ""
    while ((Get-Date) -lt $deadline) {
        try {
            $resp = Invoke-WebRequest -UseBasicParsing -Uri $Url -TimeoutSec 3
            if ($resp.StatusCode -eq 200) {
                return
            }
        } catch {
            $last = $_.Exception.Message
        }
        Start-Sleep -Milliseconds 700
    }
    throw "Timed out waiting for $Url. Last error: $last"
}

function Invoke-Checked {
    param(
        [string]$FilePath,
        [string[]]$Arguments
    )
    & $FilePath @Arguments
    $code = $LASTEXITCODE
    if ($null -eq $code) {
        $code = 0
    }
    if ($code -ne 0) {
        throw "[visible-manual] command failed ($code): $FilePath $($Arguments -join ' ')"
    }
}

function Stop-NoVnc {
    $existing = @(docker ps -a --format "{{.Names}}" 2>$null)
    foreach ($name in @("secchat-novnc-client1", "secchat-novnc-client2")) {
        if ($existing -contains $name) {
            docker rm -f $name 2>$null | Out-Null
        }
    }
}

function Start-NoVnc {
    if ($NoMonitor) {
        return
    }
    try {
        Stop-NoVnc
        $proxyCmd = "python3 -m pip install --quiet websockify && rm -rf /tmp/noVNC && git clone --depth 1 https://github.com/novnc/noVNC.git /tmp/noVNC >/tmp/novnc-git.log 2>&1 && /tmp/noVNC/utils/novnc_proxy --listen 0.0.0.0:6080 --vnc {0}:5900"
        docker run -d --name secchat-novnc-client1 --network secchat_chat -p 6081:6080 secchat-client1 sh -lc ($proxyCmd -f "chat-client1") | Out-Null
        docker run -d --name secchat-novnc-client2 --network secchat_chat -p 6082:6080 secchat-client2 sh -lc ($proxyCmd -f "chat-client2") | Out-Null
        Start-Sleep -Seconds 4
        $url1 = "http://localhost:6081/vnc.html?autoconnect=true&password=docker&resize=scale"
        $url2 = "http://localhost:6082/vnc.html?autoconnect=true&password=docker&resize=scale"
        Write-Host "[visible-manual] noVNC monitor: client1=$url1"
        Write-Host "[visible-manual] noVNC monitor: client2=$url2"
        Start-Process $url1
        Start-Process $url2
    } catch {
        Write-Host "[visible-manual] noVNC monitor unavailable: $($_.Exception.Message)"
        Write-Host "[visible-manual] fallback VNC ports: client1=5901, client2=5902, password=docker"
    }
}

$exitCode = 0

try {
    Write-Host "[visible-manual] artifact dir: $ArtifactDir"
    Write-Host "[visible-manual] resetting Docker containers and volumes"

    Stop-NoVnc

    $env:SECCHAT_TEST_PROBE = "1"
    $env:SECCHAT_TEST_PROBE_INTERVAL_MS = "150"
    $env:SECCHAT_VISIBLE_MANUAL = "1"
    $env:SECCHAT_VISIBLE_MANUAL_DELAY = [string]$DelaySeconds
    $env:SECCHAT_VISIBLE_ARTIFACT_DIR = $ArtifactDir
    $env:PYTHONIOENCODING = "utf-8"
    if ($IncludeDestructive) {
        $env:SECCHAT_VISIBLE_MANUAL_INCLUDE_DESTRUCTIVE = "1"
    } else {
        Remove-Item Env:\SECCHAT_VISIBLE_MANUAL_INCLUDE_DESTRUCTIVE -ErrorAction SilentlyContinue
    }

    Invoke-Checked "docker" @("compose", "down", "-v")
    Invoke-Checked "docker" @("compose", "up", "-d", "--build")

    Write-Host "[visible-manual] waiting for server and auditor"
    Wait-HttpOk -Url "http://localhost:18889/readyz" -TimeoutSeconds 120
    Wait-HttpOk -Url "http://localhost:18890/readyz" -TimeoutSeconds 120

    Write-Host "[visible-manual] seeding demo users"
    Invoke-Checked "python" @("tools\seed_demo_users.py")

    Write-Host "[visible-manual] VNC ports: client1=5901, client2=5902, password=docker"
    Start-NoVnc
    Write-Host "[visible-manual] running visible checklist test"

    Invoke-Checked "python" @("tests\test_visible_manual_checklist_vnc.py", "-v")
} catch {
    $exitCode = 1
    Write-Host $_
} finally {
    Write-Host "[visible-manual] reseeding demo users for manual inspection"
    try {
        & python "tools\seed_demo_users.py"
    } catch {
        Write-Host "[visible-manual] reseed failed: $($_.Exception.Message)"
    }
    Write-Host "[visible-manual] final VNC ports: client1=5901, client2=5902, password=docker"
    if (-not $NoMonitor) {
        Write-Host "[visible-manual] noVNC if available: client1=http://localhost:6081/vnc.html client2=http://localhost:6082/vnc.html"
    }
}

exit $exitCode
