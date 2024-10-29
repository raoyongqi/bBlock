@echo off
setlocal enabledelayedexpansion

rem 设置 Chrome 可执行文件路径和扩展目录
set chrome_path="C:\Program Files\Google\Chrome\Application\chrome.exe"  rem 替换为你的 Chrome 可执行文件路径
set extensions_path="C:\Users\r\Desktop\Bblock\release"

set load_extensions=""

rem 遍历扩展目录并构建加载扩展的路径
for /d %%i in (%extensions_path%\*) do (
    set load_extensions=!load_extensions!%%i,
)

rem 移除最后一个逗号
set load_extensions=!load_extensions:~0,-1!

rem 启动 Chrome，禁用 Global Media Controls 并加载扩展
start "" %chrome_path% --disable-features=GlobalMediaControls --load-extension=!load_extensions!
