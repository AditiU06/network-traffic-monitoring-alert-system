@echo off
REM ============================================================================
REM Team 14 - Network Traffic Monitoring and Alert System
REM Test Suite Runner (All Python Tests)
REM ============================================================================

setlocal
cd /d "%~dp0"

set PYTHON_CMD=
IF EXIST ".venv\Scripts\python.exe" (
    set "PYTHON_CMD=.venv\Scripts\python.exe"
) ELSE IF EXIST "%USERPROFILE%\Downloads\d1\Network Traffic Monitoring And Alert System\.venv\Scripts\python.exe" (
    set "PYTHON_CMD=%USERPROFILE%\Downloads\d1\Network Traffic Monitoring And Alert System\.venv\Scripts\python.exe"
) ELSE (
    set "PYTHON_CMD=python"
)

set PYTHONPATH=%CD%;%CD%\E1_Concurrent_Log_Processing;%CD%\E3_E4_Backend\backend;%CD%\E2_Threat_Detection;%CD%\Integration\Contracts
echo Using Python: %PYTHON_CMD%

echo ============================================================================
echo 1/4 Running E1 Concurrent Log Processing Tests (7 tests)...
echo ============================================================================
"%PYTHON_CMD%" -m unittest discover -s E1_Concurrent_Log_Processing\tests -v
IF ERRORLEVEL 1 exit /b 1

echo.
echo ============================================================================
echo 2/4 Running E2 Threat Detection Tests (44 tests)...
echo ============================================================================
"%PYTHON_CMD%" -m unittest discover -s E2_Threat_Detection\tests -v
IF ERRORLEVEL 1 exit /b 1

echo.
echo ============================================================================
echo 3/4 Running E3/E4 Backend Tests (46 tests)...
echo ============================================================================
"%PYTHON_CMD%" -m pytest E3_E4_Backend\backend\tests -q
IF ERRORLEVEL 1 exit /b 1

echo.
echo ============================================================================
echo 4/4 Running Integration Coordinator Tests (3 tests)...
echo ============================================================================
"%PYTHON_CMD%" -m pytest Integration\Orchestration\test_coordinator.py -v
IF ERRORLEVEL 1 exit /b 1

echo.
echo ============================================================================
echo ALL 100 TESTS PASSED SUCCESSFULLY!
echo ============================================================================

endlocal
