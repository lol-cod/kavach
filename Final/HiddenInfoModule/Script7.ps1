# Function to check if an alternate data stream is hidden
function IsAlternateDataStreamHidden($filePath, $streamName) {
    $streamInfo = Get-Item -Path $filePath -Stream $streamName -ErrorAction SilentlyContinue
    return -not [string]::IsNullOrEmpty($streamInfo)
}

# Specify the file path and alternate data stream name to analyze
$filePath = "C:\Path\To\File.txt"
$streamName = "MyHiddenStream"

# Check if the specified alternate data stream is hidden
if (IsAlternateDataStreamHidden $filePath $streamName) {
    Write-Host "Hidden alternate data stream detected for file $($filePath) with stream name $($streamName)!"
} else {
    Write-Host "No hidden alternate data stream detected for file $($filePath) with stream name $($streamName)."
}