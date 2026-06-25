param(
    [string]$OutputDir = ".ops_backups",
    [string]$Container = "chat-db",
    [string]$Database = "chatdb",
    [string]$User = "root",
    [string]$Password = $env:MYSQL_ROOT_PASSWORD
)

$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
if ([System.IO.Path]::IsPathRooted($OutputDir)) {
    $backupDir = $OutputDir
} else {
    $backupDir = Join-Path $repoRoot $OutputDir
}

if (-not $Password) {
    $candidate = docker exec $Container printenv MYSQL_ROOT_PASSWORD 2>$null
    if ($LASTEXITCODE -eq 0) {
        $Password = ($candidate | Select-Object -First 1).Trim()
    }
}
if (-not $Password) {
    $Password = "rootpass"
}

New-Item -ItemType Directory -Force -Path $backupDir | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$tmpPath = Join-Path $backupDir "chatdb-$stamp.sql.tmp"
$finalPath = Join-Path $backupDir "chatdb-$stamp.sql"

& docker exec -e "MYSQL_PWD=$Password" $Container mysqldump `
    "-u$User" `
    --single-transaction `
    --routines `
    --triggers `
    --events `
    $Database > $tmpPath

if ($LASTEXITCODE -ne 0) {
    if (Test-Path -LiteralPath $tmpPath) {
        Remove-Item -LiteralPath $tmpPath -Force
    }
    throw "Database backup failed with exit code $LASTEXITCODE"
}

Move-Item -LiteralPath $tmpPath -Destination $finalPath -Force
Write-Host "Backup written to $finalPath"
