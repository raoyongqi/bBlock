function Get-ChromeProcessCount {
    $chromeProcesses = Get-Process | Where-Object { $_.ProcessName -eq "chrome" }
    if ($chromeProcesses.Count -gt 0) {
        Write-Output "Chrome is running. Process count: $($chromeProcesses.Count)"
    } else {
        Write-Output "Chrome is not running."
    }
}

# 无限循环实时监控
while ($true) {
    Clear-Host  # 清屏显示最新结果
    Get-ChromeProcessCount
    Start-Sleep -Seconds 2  # 设置检查间隔时间（例如 2 秒）
}
