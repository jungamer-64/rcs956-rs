[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('usb', 'pcsc')]
    [string] $Mode,

    [ValidateSet('x64', 'arm64')]
    [string] $Architecture = 'x64',

    [string] $WdkBin = $env:WindowsSdkVerBinPath,

    [datetime] $DriverDate = [datetime]::UtcNow
)

$ErrorActionPreference = 'Stop'
if (-not $WdkBin) {
    throw 'Set WdkBin to the versioned WDK bin directory.'
}
$stampInf = (Resolve-Path -LiteralPath (Join-Path $WdkBin 'x64/stampinf.exe')).Path
$inf2Cat = (Resolve-Path -LiteralPath (Join-Path $WdkBin 'x86/Inf2Cat.exe')).Path
$target, $infArch, $catalogOs = if ($Architecture -eq 'arm64') {
    'aarch64-pc-windows-msvc', 'arm64', '10_CO_ARM64'
} else {
    'x86_64-pc-windows-msvc', 'amd64', '10_CO_X64'
}
$fields = if ($Mode -eq 'pcsc') {
    @{
        DeviceClass = 'SmartCardReader'
        ClassGuid = '{50DD5230-BA8A-11D1-BF5D-0000F805F530}'
        UmdfService = 'Rcs956Pcsc'
        KernelClientPolicy = 'UmdfKernelModeClientPolicy = AllowKernelModeClients'
        HardwareProperties = 'HKR,,DeviceType,0x10001,0x31'
        ReaderName = 'RC-S956 Contactless Smart Card Reader'
    }
} else {
    @{
        DeviceClass = 'USBDevice'
        ClassGuid = '{88BAE032-5A81-49F0-BC3D-A4FF138216D6}'
        UmdfService = 'Rcs956Usb'
        KernelClientPolicy = ''
        HardwareProperties = "HKR,,DeviceType,0x10001,0x8000`r`nHKR,,Exclusive,0x10001,1`r`n" +
            'HKR,,Security,,"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)"'
        ReaderName = 'RC-S956 USB Reader'
    }
}

Push-Location -LiteralPath (Split-Path -Parent $PSScriptRoot)
try {
    $metadata = cargo metadata --locked --no-deps --format-version 1 | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) { throw 'cargo metadata failed.' }
    $driver = $metadata.packages | Where-Object name -eq 'rcs956-driver'
    $wdf = $metadata.metadata.wdk.'driver-model'
    $umdfVersion = "$($wdf.'umdf-version-major').$($wdf.'target-umdf-version-minor').0"
    $driverVersion = [version] $driver.version
    $infVersion = "$($driverVersion.Major).$($driverVersion.Minor).$($driverVersion.Build).0"
    $infDate = $DriverDate.ToString('MM/dd/yyyy', [Globalization.CultureInfo]::InvariantCulture)

    $build = Join-Path $metadata.target_directory "driver-build/$Mode"
    cargo build --locked --release --target $target --target-dir $build -p $driver.name --features $Mode
    if ($LASTEXITCODE -ne 0) { throw 'Driver build failed.' }

    $suffix = [guid]::NewGuid().ToString('N')
    $package = Join-Path $metadata.target_directory "driver-packages/$Mode-$Architecture-$suffix"
    $null = New-Item -ItemType Directory -Path $package
    $inf = Join-Path $package 'rcs956_driver.inf'
    $source = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'rcs956_driver.inx')
    foreach ($key in $fields.Keys) {
        $source = $source.Replace("@$key@", $fields[$key])
    }
    [IO.File]::WriteAllText($inf, $source, [Text.Encoding]::ASCII)
    Copy-Item -LiteralPath (Join-Path $build "$target/release/rcs956_driver.dll") -Destination $package
    & $stampInf -f $inf -a $infArch -d $infDate -v $infVersion -u $umdfVersion
    if ($LASTEXITCODE -ne 0) { throw 'StampInf failed.' }
    & $inf2Cat "/driver:$package" "/os:$catalogOs"
    if ($LASTEXITCODE -ne 0) { throw 'Inf2Cat failed.' }
    Write-Output $package
} finally {
    Pop-Location
}
