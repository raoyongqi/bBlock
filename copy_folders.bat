@echo off
setlocal

set source="C:\Users\r\Desktop\Bblock\Bblock"
set destination="C:\Users\r\Desktop\Bblock\release"

for /l %%i in (1,1,100) do (
    xcopy %source% %destination%\urlblocker%%i /E /I
)

endlocal
