@echo off
REM Local packaging for Windows: builds sagashield-mcp and zips dist/.
REM Usage: scripts\package_local.bat
setlocal EnableDelayedExpansion

cd /d "%~dp0.."

for /f "tokens=2 delims== " %%v in ('findstr "^version" Cargo.toml') do (
    if not defined RAWVER set RAWVER=%%v
)
set VERSION=%RAWVER:"=%
set ZIP=dist\sagashield-v%VERSION%-windows-x64.zip

echo [1/4] cargo build --release --bin sagashield-mcp
cargo build --release --bin sagashield-mcp
if errorlevel 1 exit /b %errorlevel%

echo [2/4] staging dist/
if not exist dist mkdir dist
copy /y target\release\sagashield-mcp.exe dist\ >nul
copy /y README.md dist\ >nul
copy /y LICENSE-MIT dist\ >nul

echo [3/4] packing %ZIP%
if exist "%ZIP%" del "%ZIP%"
powershell -NoProfile -Command "Compress-Archive -LiteralPath 'dist\sagashield-mcp.exe','dist\README.md','dist\LICENSE-MIT' -DestinationPath '%ZIP%'"
if errorlevel 1 exit /b %errorlevel%

echo [4/4] SHA256SUMS.txt
powershell -NoProfile -Command "$h = (Get-FileHash -LiteralPath '%ZIP%' -Algorithm SHA256).Hash.ToLower(); \"$h  %ZIP%\" | Out-File -Encoding ascii dist\SHA256SUMS.txt"
if errorlevel 1 exit /b %errorlevel%

echo OK: %ZIP%
type dist\SHA256SUMS.txt
