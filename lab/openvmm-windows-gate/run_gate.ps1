$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Commit = '1dfc6bf1ed47bfc5b89c941886127525de24b191'
$Lab = Join-Path $env:GITHUB_WORKSPACE 'lab\openvmm-windows-gate'
$Results = Join-Path $Lab (Join-Path 'results' $env:GITHUB_RUN_ID)
$Vulnerable = Join-Path $env:RUNNER_TEMP 'openvmm-vulnerable'
$Fixed = Join-Path $env:RUNNER_TEMP 'openvmm-fixed'
$Wsl = Join-Path $env:RUNNER_TEMP 'WSL-current'
$Tests = Join-Path $Lab 'windows_raw_fuse_tests.rs'
$Prepare = Join-Path $Lab 'prepare_source.py'

New-Item -ItemType Directory -Force -Path $Results | Out-Null
$Transcript = Join-Path $Results 'POWERSHELL_TRANSCRIPT.log'
Start-Transcript -Path $Transcript -Force | Out-Null

$InfraErrors = [System.Collections.Generic.List[string]]::new()
$ReadRc = $null
$WriteRc = $null
$FixedReadRc = $null
$FixedWriteRc = $null
$JunctionPass = $false
$SourcePass = $false
$WslExternalRestricted = $false
$WslCreateVirtiofs = $false
$WslAddChild = $false
$WslDeviceHostPackage = $false

function Invoke-NativeLogged {
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][string]$WorkingDirectory,
        [Parameter(Mandatory=$true)][string]$LogFile,
        [Parameter(Mandatory=$true)][scriptblock]$Command
    )
    Push-Location $WorkingDirectory
    try {
        & $Command 2>&1 | Tee-Object -FilePath $LogFile
        $rc = $LASTEXITCODE
        if ($null -eq $rc) { $rc = 0 }
        return [int]$rc
    }
    finally {
        Pop-Location
    }
}

try {
    # Independent Windows path-semantics differential, 100/100.
    try {
        $Base = Join-Path $env:RUNNER_TEMP ('openvmm-junction-' + [guid]::NewGuid().ToString('N'))
        $Root = Join-Path $Base 'share'
        $Outside = Join-Path $Base 'outside'
        New-Item -ItemType Directory -Force -Path $Root,$Outside | Out-Null
        Set-Content -LiteralPath (Join-Path $Outside 'host-secret.txt') -Value 'WINDOWS_OUTSIDE_SENTINEL' -NoNewline
        $Escape = Join-Path $Root 'escape'
        cmd /c "mklink /J `"$Escape`" `"$Outside`"" 2>&1 |
            Set-Content -LiteralPath (Join-Path $Results 'JUNCTION_CREATE.log')
        if (-not (Test-Path -LiteralPath $Escape)) { throw 'junction creation failed' }
        $ReadCount = 0
        $WriteCount = 0
        $FixedBlockCount = 0
        for ($i = 1; $i -le 100; $i++) {
            $Joined = Join-Path $Escape 'host-secret.txt'
            if ((Get-Content -LiteralPath $Joined -Raw) -eq 'WINDOWS_OUTSIDE_SENTINEL') { $ReadCount++ }
            $OutFile = Join-Path $Escape ("guest-created-$i.txt")
            Set-Content -LiteralPath $OutFile -Value ("WRITE-$i") -NoNewline
            if ((Get-Content -LiteralPath (Join-Path $Outside ("guest-created-$i.txt")) -Raw) -eq ("WRITE-$i")) {
                $WriteCount++
            }
            $Parent = Get-Item -LiteralPath $Escape -Force
            $IsReparse = (($Parent.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
            if ($IsReparse) { $FixedBlockCount++ }
        }
        $JunctionPass = ($ReadCount -eq 100 -and $WriteCount -eq 100 -and $FixedBlockCount -eq 100)
        [ordered]@{
            schema = 'windows-intermediate-junction-differential-v3'
            read_outside_100x = $ReadCount
            write_outside_100x = $WriteCount
            patched_parent_reparse_reject_100x = $FixedBlockCount
            pass = $JunctionPass
        } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Results 'WINDOWS_JUNCTION_GATE.json')
        Remove-Item -LiteralPath $Base -Recurse -Force
    }
    catch {
        $InfraErrors.Add("junction_gate: $($_.Exception.Message)")
    }

    # Toolchain metadata.
    rustup toolchain install 1.95.0 --profile minimal 2>&1 |
        Tee-Object -FilePath (Join-Path $Results 'RUSTUP_INSTALL.log')
    rustc +1.95.0 --version | Set-Content -LiteralPath (Join-Path $Results 'RUSTC_VERSION.txt')
    cargo +1.95.0 --version | Set-Content -LiteralPath (Join-Path $Results 'CARGO_VERSION.txt')
    cmake --version | Set-Content -LiteralPath (Join-Path $Results 'CMAKE_VERSION.txt')

    $ProtocRoot = Join-Path $env:RUNNER_TEMP 'protoc-35'
    $ProtocZip = Join-Path $env:RUNNER_TEMP 'protoc-35.zip'
    Invoke-WebRequest -Uri 'https://github.com/protocolbuffers/protobuf/releases/download/v35.0/protoc-35.0-win64.zip' -OutFile $ProtocZip
    Expand-Archive -LiteralPath $ProtocZip -DestinationPath $ProtocRoot -Force
    $env:PROTOC = Join-Path $ProtocRoot 'bin\protoc.exe'
    & $env:PROTOC --version | Set-Content -LiteralPath (Join-Path $Results 'PROTOC_VERSION.txt')

    # Vulnerable current source.
    git clone --filter=blob:none https://github.com/microsoft/openvmm.git $Vulnerable 2>&1 |
        Tee-Object -FilePath (Join-Path $Results 'OPENVMM_CLONE.log')
    Push-Location $Vulnerable
    git checkout --detach $Commit
    if ((git rev-parse HEAD).Trim() -ne $Commit) { throw 'OpenVMM commit mismatch' }
    git rev-parse HEAD | Set-Content -LiteralPath (Join-Path $Results 'SOURCE_COMMIT.txt')
    Pop-Location

    python $Prepare --repo $Vulnerable --tests $Tests --results $Results --mode vulnerable
    $SourceGate = Get-Content -LiteralPath (Join-Path $Results 'SOURCE_CHILD_PATH_GATE.json') -Raw | ConvertFrom-Json
    $SourcePass = [bool]$SourceGate.pass
    Push-Location $Vulnerable
    cargo +1.95.0 fmt --all
    git diff --check | Set-Content -LiteralPath (Join-Path $Results 'VULNERABLE_DIFF_CHECK.log')
    git diff --stat | Set-Content -LiteralPath (Join-Path $Results 'VULNERABLE_DIFF_STAT.txt')
    Pop-Location

    $ReadRc = Invoke-NativeLogged -Name 'vulnerable-read' -WorkingDirectory $Vulnerable `
        -LogFile (Join-Path $Results 'VULNERABLE_WINDOWS_READ.log') `
        -Command { cargo +1.95.0 test -p virtiofs integration_tests::audit_windows_raw_symlink_parent_reads_outside_share -- --exact --nocapture }
    $ReadRc | Set-Content -LiteralPath (Join-Path $Results 'VULNERABLE_WINDOWS_READ.rc')

    $WriteRc = Invoke-NativeLogged -Name 'vulnerable-write' -WorkingDirectory $Vulnerable `
        -LogFile (Join-Path $Results 'VULNERABLE_WINDOWS_WRITE.log') `
        -Command { cargo +1.95.0 test -p virtiofs integration_tests::audit_windows_raw_symlink_parent_creates_outside_share -- --exact --nocapture }
    $WriteRc | Set-Content -LiteralPath (Join-Path $Results 'VULNERABLE_WINDOWS_WRITE.rc')

    # Independent fixed kill-control source tree.
    git clone --filter=blob:none https://github.com/microsoft/openvmm.git $Fixed 2>&1 |
        Tee-Object -FilePath (Join-Path $Results 'OPENVMM_FIXED_CLONE.log')
    Push-Location $Fixed
    git checkout --detach $Commit
    if ((git rev-parse HEAD).Trim() -ne $Commit) { throw 'fixed OpenVMM commit mismatch' }
    Pop-Location
    python $Prepare --repo $Fixed --tests $Tests --results $Results --mode vulnerable
    python $Prepare --repo $Fixed --tests $Tests --results $Results --mode fixed
    Push-Location $Fixed
    cargo +1.95.0 fmt --all
    git diff --check | Set-Content -LiteralPath (Join-Path $Results 'FIXED_DIFF_CHECK.log')
    git diff -- vm/devices/virtio/virtiofs/src/inode.rs vm/devices/virtio/virtiofs/src/integration_tests.rs |
        Set-Content -LiteralPath (Join-Path $Results 'MINIMAL_FIX_KILL.patch')
    Pop-Location

    $FixedReadRc = Invoke-NativeLogged -Name 'fixed-read' -WorkingDirectory $Fixed `
        -LogFile (Join-Path $Results 'FIXED_WINDOWS_READ.log') `
        -Command { cargo +1.95.0 test -p virtiofs integration_tests::audit_windows_raw_symlink_parent_reads_outside_share -- --exact --nocapture }
    $FixedReadRc | Set-Content -LiteralPath (Join-Path $Results 'FIXED_WINDOWS_READ.rc')

    $FixedWriteRc = Invoke-NativeLogged -Name 'fixed-write' -WorkingDirectory $Fixed `
        -LogFile (Join-Path $Results 'FIXED_WINDOWS_WRITE.log') `
        -Command { cargo +1.95.0 test -p virtiofs integration_tests::audit_windows_raw_symlink_parent_creates_outside_share -- --exact --nocapture }
    $FixedWriteRc | Set-Content -LiteralPath (Join-Path $Results 'FIXED_WINDOWS_WRITE.rc')

    # Current public WSL product-plumbing evidence.
    git clone --filter=blob:none https://github.com/microsoft/WSL.git $Wsl 2>&1 |
        Tee-Object -FilePath (Join-Path $Results 'WSL_CLONE.log')
    Push-Location $Wsl
    git rev-parse HEAD | Set-Content -LiteralPath (Join-Path $Results 'WSL_COMMIT.txt')
    $Hits = Get-ChildItem -Recurse -File -Include *.cpp,*.cxx,*.cc,*.h,*.hpp,*.props,*.targets,packages.lock.json,*.vcxproj |
        Select-String -Pattern 'ExternalRestricted|CreateVirtiofsDevice|AddVirtiofsChild|Microsoft.WSL.DeviceHost' -SimpleMatch:$false
    $Hits | ForEach-Object { "$($_.Path):$($_.LineNumber):$($_.Line.Trim())" } |
        Set-Content -LiteralPath (Join-Path $Results 'WSL_PRODUCT_CHAIN_HITS.txt')
    $HitText = ($Hits | ForEach-Object { $_.Line }) -join "`n"
    $WslExternalRestricted = $HitText.Contains('ExternalRestricted')
    $WslCreateVirtiofs = $HitText.Contains('CreateVirtiofsDevice')
    $WslAddChild = $HitText.Contains('AddVirtiofsChild')
    $WslDeviceHostPackage = $HitText.Contains('Microsoft.WSL.DeviceHost')
    Pop-Location
}
catch {
    $InfraErrors.Add("top_level: $($_.Exception.Message)")
    $_ | Out-String | Set-Content -LiteralPath (Join-Path $Results 'TOP_LEVEL_EXCEPTION.txt')
}
finally {
    $ExactRead = ($ReadRc -eq 0)
    $ExactWrite = ($WriteRc -eq 0)
    $FixedRead = ($FixedReadRc -eq 0)
    $FixedWrite = ($FixedWriteRc -eq 0)
    $TechnicalPass = (
        $JunctionPass -and $SourcePass -and $ExactRead -and $ExactWrite -and
        $FixedRead -and $FixedWrite -and $WslExternalRestricted -and
        $WslCreateVirtiofs -and $WslAddChild -and $WslDeviceHostPackage -and
        $InfraErrors.Count -eq 0
    )
    $Report = [ordered]@{
        schema = 'openvmm-windows-exact-source-gate-v4'
        generated_utc = [DateTime]::UtcNow.ToString('o')
        openvmm_commit = $Commit
        junction_semantics_pass = $JunctionPass
        current_source_sequence_pass = $SourcePass
        vulnerable_windows_read_test_rc = $ReadRc
        vulnerable_windows_write_test_rc = $WriteRc
        fixed_windows_read_test_rc = $FixedReadRc
        fixed_windows_write_test_rc = $FixedWriteRc
        exact_windows_openvmm_read_escape = $ExactRead
        exact_windows_openvmm_write_escape = $ExactWrite
        fixed_read_blocks = $FixedRead
        fixed_write_blocks = $FixedWrite
        wsl_external_restricted_hit = $WslExternalRestricted
        wsl_create_virtiofs_hit = $WslCreateVirtiofs
        wsl_add_child_hit = $WslAddChild
        wsl_devicehost_package_hit = $WslDeviceHostPackage
        infra_errors = @($InfraErrors)
        technical_gate_pass = $TechnicalPass
        shipping_devicehost_binary_binding = $false
        packaged_wsl_guest_runtime_repro = $false
        external_restricted_boundary_escape = $false
        functioning_control_flow_proof = $false
        confirmed_high = $false
        confirmed_critical = $false
        submission_ready = $false
    }
    $Report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $Results 'WINDOWS_EXACT_SOURCE_GATE.json')

    $Files = Get-ChildItem -LiteralPath $Results -File | Where-Object { $_.Name -ne 'SHA256SUMS.txt' } | Sort-Object Name
    $SumLines = foreach ($File in $Files) {
        $Hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $File.FullName).Hash.ToLowerInvariant()
        "$Hash  $($File.Name)"
    }
    $SumLines | Set-Content -LiteralPath (Join-Path $Results 'SHA256SUMS.txt')
    Stop-Transcript | Out-Null
}

# The JSON is the authority. Keep transport successful even when the technical gate is negative.
exit 0
