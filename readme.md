#  打包

Invoke-PS2EXE .\Monitor-Chrome2.ps1 .\ChromeMonitor.exe -NoConsole


# 快捷方式放在启动文件夹下，而不是exe


#   清理之前构建的内容
./mach clobber

#  重新构建
./mach build
