
$hiddenThreads = @()

Get-WmiObject Win32_Thread | ForEach-Object {
    $thread = $_
    $process = Get-WmiObject Win32_Process -Filter "ProcessId = $($thread.ProcessHandle)"

    if ($null -eq $process) {
        $hiddenThreads += $thread
    }
}

if ($hiddenThreads.Count -gt 0) {
    Write-Host "Hidden threads detected:"
    $hiddenThreads | ForEach-Object {
        Write-Host "Thread ID: $($_.Handle), Process ID: $($_.ProcessHandle)"
    }
} else {
    Write-Host "No hidden threads detected."
}
