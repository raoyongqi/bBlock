# Main function to monitor Chrome processes
function Start-ChromeMonitoring {
    while ($true) {
        # Get the count of Chrome processes
        $chromeProcesses = Get-Process chrome -ErrorAction SilentlyContinue

        # Check if any Chrome processes exist
        if ($chromeProcesses) {
            $chromeCount = $chromeProcesses.Count

            # Check if the count is greater than 113 or less than 100
            if ($chromeCount -gt 113 -or $chromeCount -lt 100) {
                # Stop all Chrome processes
                Stop-Process -Name chrome -Force
            } else {
            }
        } else {
        }

        # Check every 10 seconds
        Start-Sleep -Seconds 10
    }
}

# Test by running directly in a PowerShell window
Start-ChromeMonitoring
