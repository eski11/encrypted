$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location -LiteralPath $repoRoot
try {
    $nodeCommand = Get-Command node.exe -ErrorAction SilentlyContinue
    $cachedNode = Join-Path $env:USERPROFILE '.cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe'
    $nodePath = if ($nodeCommand) { $nodeCommand.Source } elseif (Test-Path -LiteralPath $cachedNode) { $cachedNode } else { Join-Path $repoRoot 'runtime\node.exe' }
    if (-not (Test-Path -LiteralPath $nodePath)) { throw 'Node.js 24 is required for source tests. The packaged server also includes runtime\node.exe.' }
    $version = & $nodePath --version
    if ($version -notmatch '^v24\.') { throw 'Run these tests with Node.js 24.' }
    if (-not (Test-Path -LiteralPath 'node_modules\@hpke\core') -or -not (Test-Path -LiteralPath 'node_modules\@signalapp\libsignal-client')) { throw 'Install the locked source dependencies with pnpm install --frozen-lockfile --ignore-scripts first.' }
    # Always test source with disposable fixtures, regardless of inherited overrides.
    $previousModule = $env:ENCPTD_TEST_SERVER_MODULE
    Remove-Item Env:ENCPTD_TEST_SERVER_MODULE -ErrorAction SilentlyContinue
    try {
        Write-Host 'Checking public app configuration...'
        & $nodePath scripts/validate-configuration.mjs
        if ($LASTEXITCODE -ne 0) { throw 'App configuration check failed.' }
        Write-Host 'Testing temporary local servers, encrypted transport, accounts and deletion rules...'
        $testFiles = @(Get-ChildItem -LiteralPath 'desktop\test' -Filter '*.test.mjs' | ForEach-Object { $_.FullName })
        & $nodePath --test @testFiles
        if ($LASTEXITCODE -ne 0) { throw 'Local integration tests failed.' }
    } finally {
        if ($null -eq $previousModule) { Remove-Item Env:ENCPTD_TEST_SERVER_MODULE -ErrorAction SilentlyContinue }
        else { $env:ENCPTD_TEST_SERVER_MODULE = $previousModule }
    }
    Write-Host 'LOCAL CHECKS PASSED. Tests used temporary accounts and databases, without connecting to your live server.' -ForegroundColor Green
    Write-Host 'This does not run an IPA or verify iPhone typing/Face ID/Keychain behaviour. Codemagic runs Swift simulator tests before packaging; check the interface on the phones afterward.'
} catch {
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
} finally { Pop-Location }
