[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-z0-9][a-z0-9._=-]{0,63}$')][string]$Username,
    [switch]$Admin
)

$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    if (-not (Test-Path -LiteralPath '.env')) { throw 'Run Start-Server.ps1 first.' }
    $chatRole = if ($Admin) { '--admin' } else { '--no-admin' }
    # The container prompts for the password; it never appears in shell arguments.
    docker compose exec synapse register_new_matrix_user -c /data/homeserver.yaml -u $Username $chatRole http://127.0.0.1:8008
    if ($LASTEXITCODE -ne 0) { throw 'Account creation failed.' }
} finally {
    Pop-Location
}
