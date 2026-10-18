param(
    [Parameter(Mandatory = $true)]
    [string]$AssemblyPath,
    [string]$WandDirectory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$assembly = [Reflection.Assembly]::LoadFrom((Resolve-Path -LiteralPath $AssemblyPath).Path)
Add-Type -Path (Join-Path $PSScriptRoot 'tests\StaticIntegrityTests.cs')
[StaticIntegrityTests]::Run($assembly, $WandDirectory)
