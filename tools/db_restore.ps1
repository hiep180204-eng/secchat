param(
    [Parameter(Mandatory = $true)]
    [string]$InputFile,
    [switch]$ConfirmRestore,
    [string]$Container = "chat-db",
    [string]$Database = "chatdb",
    [string]$User = "root",
    [string]$Password = $env:MYSQL_ROOT_PASSWORD
)

$ErrorActionPreference = "Stop"

if (-not $ConfirmRestore) {
    throw "Restore is destructive. Re-run with -ConfirmRestore after checking the backup file."
}

$path = Resolve-Path -LiteralPath $InputFile

if (-not $Password) {
    $candidate = docker exec $Container printenv MYSQL_ROOT_PASSWORD 2>$null
    if ($LASTEXITCODE -eq 0) {
        $Password = ($candidate | Select-Object -First 1).Trim()
    }
}
if (-not $Password) {
    $Password = "rootpass"
}

Get-Content -LiteralPath $path -Encoding UTF8 | docker exec -i -e "MYSQL_PWD=$Password" $Container mysql "-u$User" $Database

if ($LASTEXITCODE -ne 0) {
    throw "Database restore failed with exit code $LASTEXITCODE"
}

Write-Host "Restored $Database from $path"
