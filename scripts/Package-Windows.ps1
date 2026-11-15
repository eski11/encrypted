[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Destination)

$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$target = [IO.Path]::GetFullPath($Destination)
if ((Test-Path -LiteralPath $target) -and @(Get-ChildItem -LiteralPath $target -Force).Count -gt 0) {
    throw 'Choose a new empty destination. Packaging must never include an existing server database or owner token.'
}
New-Item -ItemType Directory -Force -Path $target,(Join-Path $target 'desktop'),(Join-Path $target 'runtime') | Out-Null
$downloadDirectory = Join-Path $repo 'artifacts/downloads'
New-Item -ItemType Directory -Force -Path $downloadDirectory | Out-Null
$filename = 'node-v24.22.1-win-x64.zip'
$archive = Join-Path $downloadDirectory $filename
$expected = 'd2046d28c2c3dcd211ac5145c0bf30e2047ef9dfb306693c8c6e2eccd8b95fa5'
if (-not (Test-Path -LiteralPath $archive)) {
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest ('https://nodejs.org/dist/v24.22.1/' + $filename) -OutFile $archive
}
if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected) { throw 'Node runtime checksum mismatch.' }
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [IO.Compression.ZipFile]::OpenRead($archive)
try {
    foreach ($entryName in @('node.exe','LICENSE')) {
        $entry = $zip.GetEntry('node-v24.22.1-win-x64/' + $entryName)
        if (-not $entry) { throw ('Runtime archive is missing ' + $entryName) }
        [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, (Join-Path $target ('runtime/' + $entryName)), $false)
    }
} finally { $zip.Dispose() }
& node (Join-Path $repo 'scripts/build-desktop.mjs') (Join-Path $target 'desktop')
if ($LASTEXITCODE -ne 0) { throw 'Obfuscated server build failed.' }
foreach ($file in @('Start-ENCPTD.cmd','Stop-ENCPTD.cmd','Connect-Internet-Test.cmd','Setup-Automatic-Connection.cmd','README.md','INSTALL.md','PRIVACY.md','SECURITY.md','LICENSE')) {
    Copy-Item -LiteralPath (Join-Path $repo $file) -Destination (Join-Path $target $file)
}
$outputZip = $target + '.zip'
if (Test-Path -LiteralPath $outputZip) { throw 'The destination ZIP already exists. Choose a new version/destination.' }
[IO.Compression.ZipFile]::CreateFromDirectory($target, $outputZip, [IO.Compression.CompressionLevel]::Optimal, $true)
Write-Output ('Prepared Windows server: ' + $outputZip)
