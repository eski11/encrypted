[CmdletBinding()]
param([switch]$TemporaryInternetTest)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Push-Location $PSScriptRoot
try {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        throw 'Install and open Docker Desktop with its WSL 2/Linux containers backend first. See server/README.md.'
    }
    $chatDockerOS = & docker info --format '{{.OSType}}'
    if ($LASTEXITCODE -ne 0) { throw 'Docker engine is not ready. Open Docker Desktop and wait for it to start.' }
    if ($chatDockerOS.Trim() -ne 'linux') { throw 'Switch Docker Desktop to Linux containers.' }
    docker compose version
    if ($LASTEXITCODE -ne 0) { throw 'Docker Compose is required.' }

    function Invoke-ChatCompose {
        param([string[]]$Arguments)
        & docker compose @Arguments
        if ($LASTEXITCODE -ne 0) { throw "Docker Compose failed (exit $LASTEXITCODE)." }
    }

    function New-ChatSecret {
        $buffer = New-Object byte[] 48
        $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
        try { $generator.GetBytes($buffer) } finally { $generator.Dispose() }
        return ([BitConverter]::ToString($buffer)).Replace('-', '').ToLowerInvariant()
    }

    if (-not (Test-Path -LiteralPath '.env')) {
        $chatLines = @(
            'CHAT_PUBLIC_URL=https://setup.invalid',
            ('POSTGRES_PASSWORD=' + (New-ChatSecret)),
            ('REGISTRATION_SHARED_SECRET=' + (New-ChatSecret)),
            ('MACAROON_SECRET_KEY=' + (New-ChatSecret)),
            ('FORM_SECRET=' + (New-ChatSecret))
        )
        [IO.File]::WriteAllLines((Join-Path $PSScriptRoot '.env'), $chatLines)
    }
    New-Item -ItemType Directory -Path 'state/synapse' -Force | Out-Null
    Invoke-ChatCompose -Arguments @('pull', 'db', 'synapse', 'gateway')
    if (-not (Test-Path -LiteralPath 'state/synapse/homeserver.yaml')) {
        Invoke-ChatCompose -Arguments @('run', '--rm', '--no-deps', 'synapse', 'generate')
    }
    Invoke-ChatCompose -Arguments @('run', '--rm', '--no-deps', '--entrypoint', 'python', 'synapse', '/bootstrap/configure_server.py')
    Invoke-ChatCompose -Arguments @('up', '-d', 'db', 'synapse', 'gateway')

    if ($TemporaryInternetTest) {
        Invoke-ChatCompose -Arguments @('--profile', 'temporary-tunnel', 'up', '-d', 'tunnel')
        $chatUrl = $null
        for ($attempt = 0; $attempt -lt 30; $attempt++) {
            $chatLog = (& docker compose --profile temporary-tunnel logs --no-color --tail 100 tunnel 2>&1 | Out-String)
            $chatMatches = [regex]::Matches($chatLog, 'https://[a-z0-9-]+\.trycloudflare\.com')
            if ($chatMatches.Count -gt 0) {
                $chatUrl = $chatMatches[$chatMatches.Count - 1].Value
                break
            }
            Start-Sleep -Seconds 2
        }
        if (-not $chatUrl) { throw 'The temporary tunnel did not provide an address. Check docker compose --profile temporary-tunnel logs tunnel.' }
        $chatEnv = [IO.File]::ReadAllLines((Join-Path $PSScriptRoot '.env'))
        $chatEnv = $chatEnv | ForEach-Object {
            if ($_ -match '^CHAT_PUBLIC_URL=') { 'CHAT_PUBLIC_URL=' + $chatUrl } else { $_ }
        }
        [IO.File]::WriteAllLines((Join-Path $PSScriptRoot '.env'), [string[]]$chatEnv)
        Invoke-ChatCompose -Arguments @('run', '--rm', '--no-deps', '--entrypoint', 'python', 'synapse', '/bootstrap/configure_server.py')
        Invoke-ChatCompose -Arguments @('up', '-d', '--no-deps', '--force-recreate', 'synapse', 'gateway')

        $chatReady = $false
        for ($attempt = 0; $attempt -lt 30; $attempt++) {
            try {
                $chatResponse = Invoke-RestMethod -Uri ($chatUrl + '/_matrix/client/versions') -TimeoutSec 8
                if ($chatResponse.versions) { $chatReady = $true; break }
            } catch { Start-Sleep -Seconds 2 }
        }
        if (-not $chatReady) { throw 'The public server check failed. The stack is running; check its logs before building the app.' }
        $chatClient = [ordered]@{app_name='ENCPTD'; server_name='encptd.local'; base_url=$chatUrl}
        [IO.File]::WriteAllText((Join-Path $PSScriptRoot 'client.json'), ($chatClient | ConvertTo-Json))
        Write-Host "ENCPTD test server is reachable at $chatUrl"
        Write-Host 'This address changes if the tunnel restarts. It is a test connection, not permanent hosting.'
        Write-Host 'Next: create your account with New-ChatUser.ps1. Then return to Codex to build the app for this server.'
    } else {
        Write-Host 'Local stack started at http://127.0.0.1:8009. It is not yet configured for internet access.'
    }
} finally {
    Pop-Location
}
