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

Write-Output ("WORK={0}" -f $WorkPath)
Write-Output ("CONTROLLER_ID={0}" -f $controllerId)
Write-Output ("CONTROLLER_ALIVE={0}" -f [bool](Get-Process -Id $controllerId -ErrorAction SilentlyContinue))
Write-Output ("EVIDENCE_EXISTS={0}" -f (Test-Path -LiteralPath $evidence))

$final = Join-Path $evidence 'FINAL_RESULT.txt'
$failure = Join-Path $evidence 'FAILURE.txt'
Write-Output ("FINAL_EXISTS={0}" -f (Test-Path -LiteralPath $final))
Write-Output ("FAILURE_EXISTS={0}" -f (Test-Path -LiteralPath $failure))
if (Test-Path -LiteralPath $final) {
    Write-Output '---FINAL---'
    Get-Content -LiteralPath $final
}
if (Test-Path -LiteralPath $failure) {
    Write-Output '---FAILURE---'
    Get-Content -LiteralPath $failure
}

Write-Output '---ATTEMPTS---'
if (Test-Path -LiteralPath $evidence) {
    $attemptFiles = Get-ChildItem -LiteralPath $evidence -Filter 'attack-attempt-*.json' -File |
        Sort-Object Name
    Write-Output ("ATTEMPT_RECEIPTS={0}" -f $attemptFiles.Count)
    foreach ($file in ($attemptFiles | Select-Object -Last 5)) {
        Write-Output ("FILE={0} AGE_SECONDS={1}" -f $file.Name, [int]((Get-Date) - $file.LastWriteTime).TotalSeconds)
        Get-Content -LiteralPath $file.FullName -Raw
    }
}

Write-Output '---TASKS---'
Get-ScheduledTask -ErrorAction SilentlyContinue |
    Where-Object TaskName -Like 'ZdbTaskProxy-*' |
    ForEach-Object {
        $info = Get-ScheduledTaskInfo -TaskName $_.TaskName -ErrorAction SilentlyContinue
        [pscustomobject]@{
            TaskName = $_.TaskName
            State = $_.State
            UserId = $_.Principal.UserId
            LastRunTime = $info.LastRunTime
            LastTaskResult = if ($null -ne $info) { '0x{0:X8}' -f ([uint32]$info.LastTaskResult) } else { '<none>' }
        }
    } | Format-Table -AutoSize

Write-Output '---PROCESSES---'
Get-CimInstance Win32_Process |
    Where-Object {
        $_.ProcessId -eq $controllerId -or
        $_.Name -in @('pwsh.exe', 'dotnet.exe', 'JunctionWatcher.exe', 'Procmon64.exe')
    } |
    Select-Object ProcessId, ParentProcessId, Name, CreationDate, CommandLine |
    Sort-Object CreationDate |
    Format-List

Write-Output '---LATEST_FILES---'
if (Test-Path -LiteralPath $evidence) {
    Get-ChildItem -LiteralPath $evidence -File |
        Sort-Object LastWriteTime |
        Select-Object -Last 12 Name, Length, LastWriteTime |
        Format-Table -AutoSize
}

Write-Output '---CONTROLLER_ERR---'
Get-Content -LiteralPath (Join-Path $WorkPath 'controller.stderr.txt') -Tail 12 -ErrorAction SilentlyContinue
