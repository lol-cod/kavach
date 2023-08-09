
# Function to check if a process is hidden
function IsProcessHidden($processId) {
    try {
        $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
        return $null -eq $process
    } catch {
        return $true
    }
}

# Get all running processes
$processes = Get-WmiObject Win32_Process

# Find hidden processes
$hiddenProcesses = $processes | Where-Object { IsProcessHidden $_.ProcessId }

# Display hidden processes
if ($hiddenProcesses.Count -gt 0) {
    Write-Host "Hidden processes detected:"
    $hiddenProcesses | ForEach-Object {
        Write-Host "Process ID: $($_.ProcessId), Name: $($_.Name)"
    }
} else {
    Write-Host "No hidden processes detected."
}
