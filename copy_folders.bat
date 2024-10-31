@echo off
setlocal enabledelayedexpansion

set source="C:\Users\r\Desktop\Bblock\Bblock"
set destination="C:\Users\r\Desktop\Bblock\release"

:: 生成一个随机数来确定保留原始 content.js 的文件夹编号
set /a randomFolder=%random% %% 100 + 1

for /l %%i in (1,1,100) do (
    xcopy %source% %destination%\urlblocker%%i /E /I
    if %%i NEQ !randomFolder! (
        :: 删除复制的 content.js
        del "%destination%\urlblocker%%i\content.js"
        :: 创建一个空的 content.js
        echo. > "%destination%\urlblocker%%i\content.js"
    )
)

endlocal
