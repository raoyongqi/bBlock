@echo off
setlocal enabledelayedexpansion

rem 设置 Chrome 可执行文件路径和扩展目录
set "chrome_path=C:\Program Files\Google\Chrome\Application\chrome.exe"
set "extensions_path=C:\Users\r\Desktop\Bblock\release3"

set "load_extensions="

rem 遍历扩展目录并构建加载扩展的路径
for /d %%i in (%extensions_path%\*) do (
    if defined load_extensions (
        set "load_extensions=!load_extensions!,%%i"
    ) else (
        set "load_extensions=%%i"
    )
)

rem 启动 Chrome 并加载扩展
start "" "%chrome_path%" --load-extension=!load_extensions! --enable-extensions
