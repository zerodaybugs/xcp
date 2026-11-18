param(
    [Parameter(Mandatory = $true)]
    [string]$WorkPath,

    [Parameter(Mandatory = $true)]
    [string]$EvidenceDirectoryName
)

$ErrorActionPreference = 'Continue'
$evidence = Join-Path $WorkPath $EvidenceDirectoryName
$pidPath = Join-Path $WorkPath 'controller.pid.txt'
$controllerId = if (Test-Path -LiteralPath $pidPath) {
    [int](Get-Content -LiteralPath $pidPath -Raw).Trim()
} else {
    0
}

Write-Output ("WORK_PATH={0}" -f $WorkPath)
Write-Output ("CONTROLLER_ID={0}" -f $controllerId)
Write-Output ("CONTROLLER_ALIVE={0}" -f [bool](Get-Process -Id $controllerId -ErrorAction SilentlyContinue))
Write-Output ("EVIDENCE_EXISTS={0}" -f (Test-Path -LiteralPath $evidence))

$final = Join-Path $evidence 'FINAL_RESULT.txt'
$failure = Join-Path $evidence 'FAILURE.txt'
Write-Output ("FINAL_EXISTS={0}" -f (Test-Path -LiteralPath $final))
if (Test-Path -LiteralPath $final) {
    Write-Output '---FINAL_RESULT---'
    Get-Content -LiteralPath $final
}
if (Test-Path -LiteralPath $failure) {
    Write-Output '---FAILURE---'
    Get-Content -LiteralPath $failure
}

Write-Output '---LATEST_EVIDENCE_FILES---'
if (Test-Path -LiteralPath $evidence) {
    Get-ChildItem -LiteralPath $evidence -File |
        Sort-Object LastWriteTime |
        Select-Object -Last 30 Name, Length, LastWriteTime |
        Format-Table -AutoSize
}

Write-Output '---CONTROLLER_STDERR---'
Get-Content -LiteralPath (Join-Path $WorkPath 'controller.stderr.txt') -Tail 30 -ErrorAction SilentlyContinue
Write-Output '---CONTROLLER_STDOUT---'
Get-Content -LiteralPath (Join-Path $WorkPath 'controller.stdout.txt') -Tail 30 -ErrorAction SilentlyContinue
