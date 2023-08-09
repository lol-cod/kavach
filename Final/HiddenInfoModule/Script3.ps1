# Function to check if a registry key is hidden
function IsRegistryKeyHidden($hive, $keyPath) {
    $regKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($hive, "")  # Open the specified registry hive

    try {
        $subKey = $regKey.OpenSubKey($keyPath, $false)  # Try to open the subkey
        return $subKey -eq $null
    } catch {
        return $false
    } finally {
        if ($regKey -ne $null) {
            $regKey.Close()
        }
    }
}

# Specify the registry hive and key path to analyze
$hive = [Microsoft.Win32.RegistryHive]::LocalMachine
$keyPath = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

# Check if the specified registry key is hidden
if (IsRegistryKeyHidden $hive $keyPath) {
    Write-Host "Hidden registry key detected: $keyPath"
} else {
    Write-Host "No hidden registry key detected: $keyPath"
}