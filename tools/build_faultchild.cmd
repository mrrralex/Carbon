@echo off
rem Carbon -- build tools\faultchild.cpp (the watcher self-test's native victim) with the same
rem toolchain the injector uses, without touching Carbon.sln: it is a test fixture, not a target.
setlocal
set VSDIR=C:\Program Files\Microsoft Visual Studio\18\Community
if not exist "%VSDIR%\VC\Auxiliary\Build\vcvars64.bat" (
  echo cannot find vcvars64.bat under "%VSDIR%" -- adjust VSDIR
  exit /b 2
)
call "%VSDIR%\VC\Auxiliary\Build\vcvars64.bat" >nul || exit /b 3
pushd "%~dp0"
if not exist out mkdir out
cl /nologo /O2 /MD /W3 faultchild.cpp /Foout\ /Feout\faultchild.exe /link /SUBSYSTEM:CONSOLE
set rc=%errorlevel%
popd
exit /b %rc%
