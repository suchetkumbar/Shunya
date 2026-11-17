# Runs a make target inside the WSL "Debian" distro, from Windows.
#   .\scripts\wsl.ps1 test
#   .\scripts\wsl.ps1 lab-up
# All builds and the lab run in WSL; nothing destructive ever runs on Windows.
param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Targets = @('all'))
$ErrorActionPreference = 'Stop'
$env:WSL_UTF8 = '1'
$repo = (Resolve-Path "$PSScriptRoot\..").Path
$wslRepo = (wsl.exe -d Debian -u lab -- wslpath -a ($repo -replace '\\', '/')).Trim()
wsl.exe -d Debian -u lab --cd $wslRepo -- bash -lc "make $($Targets -join ' ')"
exit $LASTEXITCODE
