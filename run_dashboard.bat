@echo off
REM ============================================================================
REM Team 14 - Network Traffic Monitoring and Alert System
REM Application Launcher (E4 Dashboard + Backend)
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

echo Starting Team 14 Network Traffic Monitoring and Alert System...
echo Target Pipeline: E4 Dashboard -^> PipelineCoordinator -^> E1 -^> E3 -^> E2 -^> E3 -^> E4
echo Dashboard will be available at: http://127.0.0.1:8000
echo Using Python: %PYTHON_CMD%
echo.

set PYTHONPATH=%CD%;%CD%\E3_E4_Backend\backend;%CD%\E2_Threat_Detection;%CD%\Integration\Contracts
"%PYTHON_CMD%" E3_E4_Backend\backend\main.py

endlocal
