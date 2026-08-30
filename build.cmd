@echo off
setlocal
cd /d "%~dp0"

echo ============================================
echo  dnsprobe - build script (v2, offline-friendly)
echo ============================================
echo.

where dotnet >nul 2>nul
if errorlevel 1 (
    echo [ERROR] The .NET SDK was not found.
    echo Install it from https://dotnet.microsoft.com/download
    echo Then close this window, open a new one, and run this script again.
    echo.
    pause
    exit /b 1
)

echo Using:
dotnet --version
echo.

echo [1/3] Building the application (tests are skipped on purpose)...
dotnet build src\DnsProbe\DnsProbe.csproj -c Release
if errorlevel 1 (
    echo.
    echo [ERROR] Build failed. Copy the red text above and send it back.
    pause
    exit /b 1
)
echo   OK.
echo.

echo [2/3] Trying a standalone build (no .NET needed on other PCs)...
dotnet publish src\DnsProbe\DnsProbe.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o "%~dp0publish" >"%TEMP%\dnsprobe_sc.log" 2>&1
if not errorlevel 1 goto :done_selfcontained

echo   Standalone build not possible (NuGet is unreachable).
echo   Falling back to the light build.
echo.

echo [3/3] Light build (needs .NET 8 installed on the machine that runs it)...
dotnet publish src\DnsProbe\DnsProbe.csproj -c Release -o "%~dp0publish"
if errorlevel 1 (
    echo.
    echo [ERROR] Publish failed. Copy the red text above and send it back.
    pause
    exit /b 1
)
echo.
echo ============================================
echo  DONE - light build
echo  Executable: %~dp0publish\dnsprobe.exe
echo  NOTE: another PC needs the .NET 8 Runtime to run this file.
echo ============================================
goto :try_it

:done_selfcontained
echo   OK.
echo.
echo ============================================
echo  DONE - standalone build
echo  Executable: %~dp0publish\dnsprobe.exe
echo  This file runs on any Windows x64 PC, no install needed.
echo ============================================

:try_it
echo.
echo Try it now:
echo     publish\dnsprobe.exe --interfaces
echo.
pause
