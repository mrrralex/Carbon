@echo off
rem Carbon - menu UI launcher. Double-click this file.
rem injector.exe with no arguments opens the UI too, so double-clicking the exe works; this stays
rem as a launcher that names the build it expects and says what to do when it is missing.
setlocal
set "EXE=%~dp0bin\Release\injector.exe"
if not exist "%EXE%" (
    echo The UI has not been built yet. Build it with:
    echo   msbuild inject\injector.vcxproj -p:Configuration=Release -p:Platform=x64
    echo   ^(or open Carbon.sln in Visual Studio and build Release^|x64^)
    pause
    exit /b 1
)
start "" "%EXE%" --ui
exit /b 0
