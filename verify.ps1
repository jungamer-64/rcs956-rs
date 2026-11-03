$ErrorActionPreference = 'Stop'
$savedRustdocFlags = $env:RUSTDOCFLAGS
Push-Location $PSScriptRoot
try {
    cargo fmt --check
    if ($LASTEXITCODE -ne 0) { throw 'Formatting failed' }
    cargo test --locked
    if ($LASTEXITCODE -ne 0) { throw 'Tests failed' }
    cargo clippy --locked --all-targets -- -D warnings
    if ($LASTEXITCODE -ne 0) { throw 'Clippy failed' }
    $env:RUSTDOCFLAGS = '-D warnings'
    cargo doc --locked --no-deps
    if ($LASTEXITCODE -ne 0) { throw 'Rustdoc failed' }
} finally {
    $env:RUSTDOCFLAGS = $savedRustdocFlags
    Pop-Location
}
