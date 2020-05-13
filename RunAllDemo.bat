@ECHO OFF
@COLOR 1A
ECHO ========================Run all demos for x86-Debug==============================
pushd .
CD output\demo\x86\Debug
FOR /r %%i IN (*.exe) DO (
	ECHO Running:%%i
	%%i
)
popd

ECHO ========================Run all demos for x86-Release==============================
pushd .
CD output\demo\x86\Release
FOR /r %%i IN (*.exe) DO (
	ECHO Running:%%i
	%%i
)
popd

ECHO ========================Run all demos for x64-Debug==============================
pushd .
CD output\demo\x64\Debug
FOR /r %%i in (*.exe) DO (
	ECHO Running:%%i
	%%i
)
popd

ECHO ========================Run all demos for x64-Release==============================
pushd .
CD output\demo\x64\Release
FOR /r %%i in (*.exe) DO (
	ECHO Running:%%i
	%%i
)
popd

pause