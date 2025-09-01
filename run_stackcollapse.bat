@echo off
setlocal

REM Usage check
if "%~1"=="" (
  echo Usage: %~nx0 ^<perf_data_file^>
  echo Example: %~nx0 perf_icache.data
  exit /b 1
)

set "DATA_FILE=%~1"
if not exist "%DATA_FILE%" (
  echo Error: Data file not found: "%DATA_FILE%"
  exit /b 1
)

REM Locate script alongside this .bat
set "SCRIPT_DIR=%~dp0"
set "SCRIPT=%SCRIPT_DIR%stackcollapse_simpleperf.py"
if not exist "%SCRIPT%" (
  echo Error: Script not found: "%SCRIPT%"
  exit /b 1
)

REM Prefer NDK Python if available; otherwise fallback to system python
set "PY=C:\Android\android-ndk\toolchains\llvm\prebuilt\windows-x86_64\python3\python.exe"
if exist "%PY%" (
  REM using NDK Python
) else (
  set "PY=python"
)

"%PY%" "%SCRIPT%" --data "%DATA_FILE%" --dedug-first-start-thread --explain-thread "GameThread" --equalize-root-sum
set "RC=%ERRORLEVEL%"
if %RC% NEQ 0 (
  echo Failed with exit code %RC%.
  exit /b %RC%
)

echo Done.
exit /b 0
