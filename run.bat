@echo off
setlocal enabledelayedexpansion

:: Set working directory to script location
cd /d "%~dp0"

:: Set console code page to UTF-8
chcp 65001 >nul 2>&1
title APIGhost - Stateful BOLA Detection Engine

:: Set Python environment variables
set "PYTHONPATH=%~dp0src;!PYTHONPATH!"
set "PYTHONIOENCODING=utf-8"

:: Check for Python installation
python --version >nul 2>&1
if !ERRORLEVEL! equ 0 (
    set "PY_CMD=python"
    goto DETECTED
)

py --version >nul 2>&1
if !ERRORLEVEL! equ 0 (
    set "PY_CMD=py"
    goto DETECTED
)

cls
echo ========================================================================
echo  ERROR: Python is not found on your system!
echo ========================================================================
echo.
echo  APIGhost requires Python 3.12 or newer.
echo.
echo  Please download and install Python from https://www.python.org/
echo  (Make sure to check "Add Python to PATH" during installation)
echo.
echo ========================================================================
pause
exit /b 1

:DETECTED

:MENU
cls
echo ========================================================================
echo            APIGhost - Stateful BOLA Detection Engine
echo        Cross-User Authorization Testing and Vulnerability Scanner
echo ========================================================================
echo.
echo   [1] Quick Demo and Visual Graph Report  (Instant HTML report with graphs)
echo   [2] Run Live API Scan                   (Full BOLA scan against an API)
echo   [3] Preview Attack Chains               (Dry run from OpenAPI spec)
echo   [4] Run Test Suite                      (Verify project with Pytest)
echo   [5] Install or Update Dependencies      (pip install requirements)
echo   [6] View CLI Help                       (All commands and options)
echo   [7] Open Documentation and README       (Architecture and guides)
echo   [8] Exit
echo.
echo ========================================================================
choice /C 12345678 /N /M "  Select an option [1-8]: "

if errorlevel 8 goto EXIT
if errorlevel 7 goto DOCS
if errorlevel 6 goto HELP
if errorlevel 5 goto INSTALL
if errorlevel 4 goto TEST
if errorlevel 3 goto CHAINS
if errorlevel 2 goto SCAN
if errorlevel 1 goto DEMO

goto MENU


:DEMO
cls
echo ========================================================================
echo  [1] Generating Sample APIGhost Report with Visual Graphs...
echo ========================================================================
echo.
!PY_CMD! generate_sample_report.py
echo.
echo ========================================================================
echo  Demo report generated successfully!
echo ========================================================================
echo.
pause
goto MENU


:SCAN
cls
echo ========================================================================
echo  [2] Run Live API Scan (BOLA Testing)
echo ========================================================================
echo.
echo  Press ENTER to use default values shown in brackets.
echo.

set "SPEC_PATH=tests\test_spec.json"
set "USER_SPEC="
set /p "USER_SPEC=  OpenAPI Spec file [tests\test_spec.json]: "
if defined USER_SPEC (
    if not "!USER_SPEC!"=="" set "SPEC_PATH=!USER_SPEC!"
)

set "TARGET_URL=http://localhost:8000"
set "USER_TARGET="
set /p "USER_TARGET=  Target Base URL [http://localhost:8000]: "
if defined USER_TARGET (
    if not "!USER_TARGET!"=="" set "TARGET_URL=!USER_TARGET!"
)

set "TOKEN_A=token_user_a"
set "USER_TOKEN_A="
set /p "USER_TOKEN_A=  User A Token (Resource Owner) [token_user_a]: "
if defined USER_TOKEN_A (
    if not "!USER_TOKEN_A!"=="" set "TOKEN_A=!USER_TOKEN_A!"
)

set "TOKEN_B=token_user_b"
set "USER_TOKEN_B="
set /p "USER_TOKEN_B=  User B Token (Attacker) [token_user_b]: "
if defined USER_TOKEN_B (
    if not "!USER_TOKEN_B!"=="" set "TOKEN_B=!USER_TOKEN_B!"
)

set "REPORT_FMT=html"
set "USER_FMT="
set /p "USER_FMT=  Report Format (html/md/json/all) [html]: "
if defined USER_FMT (
    if not "!USER_FMT!"=="" set "REPORT_FMT=!USER_FMT!"
)

set "REPORT_OUT=report.html"
set "USER_OUT="
set /p "USER_OUT=  Report Output File [report.html]: "
if defined USER_OUT (
    if not "!USER_OUT!"=="" set "REPORT_OUT=!USER_OUT!"
)

echo.
echo  ------------------------------------------------------------------------
echo  Starting scan...
echo  Spec:   !SPEC_PATH!
echo  Target: !TARGET_URL!
echo  Format: !REPORT_FMT!
echo  Output: !REPORT_OUT!
echo  ------------------------------------------------------------------------
echo.

!PY_CMD! -m apighost scan --spec "!SPEC_PATH!" --target "!TARGET_URL!" --token-a "!TOKEN_A!" --token-b "!TOKEN_B!" --format !REPORT_FMT! --output "!REPORT_OUT!"

echo.
if exist "!REPORT_OUT!" (
    echo  Report saved to: !REPORT_OUT!
    if /i "!REPORT_FMT!"=="html" (
        set "OPEN_REP="
        set /p "OPEN_REP=  Do you want to open the report in your browser? (Y/n): "
        if /i "!OPEN_REP!"=="" start "" "!REPORT_OUT!"
        if /i "!OPEN_REP!"=="y" start "" "!REPORT_OUT!"
        if /i "!OPEN_REP!"=="yes" start "" "!REPORT_OUT!"
    )
)
echo.
pause
goto MENU


:CHAINS
cls
echo ========================================================================
echo  [3] Preview Attack Chains (Dry Run from OpenAPI Spec)
echo ========================================================================
echo.
set "SPEC_PATH=tests\test_spec.json"
set "USER_SPEC="
set /p "USER_SPEC=  OpenAPI Spec file [tests\test_spec.json]: "
if defined USER_SPEC (
    if not "!USER_SPEC!"=="" set "SPEC_PATH=!USER_SPEC!"
)

echo.
echo  Parsing spec and building attack chains...
echo.
!PY_CMD! -m apighost chains --spec "!SPEC_PATH!"
echo.
pause
goto MENU


:TEST
cls
echo ========================================================================
echo  [4] Running Project Test Suite (Pytest)
echo ========================================================================
echo.
!PY_CMD! -m pytest tests/ -v
echo.
echo ========================================================================
echo  Test run complete.
echo ========================================================================
echo.
pause
goto MENU


:INSTALL
cls
echo ========================================================================
echo  [5] Installing / Updating APIGhost and Dependencies...
echo ========================================================================
echo.
!PY_CMD! -m pip install --upgrade pip
!PY_CMD! -m pip install -e .[dev]
echo.
echo ========================================================================
echo  Installation finished.
echo ========================================================================
echo.
pause
goto MENU


:HELP
cls
echo ========================================================================
echo  [6] APIGhost CLI Help
echo ========================================================================
echo.
!PY_CMD! -m apighost --help
echo.
echo ------------------------------------------------------------------------
echo  Scan Command Options:
echo ------------------------------------------------------------------------
!PY_CMD! -m apighost scan --help
echo.
pause
goto MENU


:DOCS
cls
echo ========================================================================
echo  [7] Opening Project Documentation...
echo ========================================================================
echo.
if exist "README.md" (
    start "" "README.md"
    echo  Opened README.md
)
if exist "docs\ARCHITECTURE.md" (
    echo  Architecture guide available at docs\ARCHITECTURE.md
)
echo.
pause
goto MENU


:EXIT
cls
echo.
echo  Thank you for using APIGhost!
echo.
exit /b 0
