@ECHO OFF
@COLOR 1A
ECHO ========================Run all demo for x86==============================
@CD .\output\demo\Win32\
FOR /r .\ %%i IN (*.exe) DO (
	ECHO %%i
	%%i
)

ECHO ========================Run all demo for x64==============================
@CD .\output\demo\x64\
FOR /r .\ %%i in (*.exe) DO (
	ECHO %%i
	%%i
)