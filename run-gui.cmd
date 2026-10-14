@echo off
rem ---------------------------------------------------------------------------
rem One-click launcher for the cgpt GUI.
rem
rem Double-click this file, or run from a terminal:
rem     run-gui.cmd              launch
rem     run-gui.cmd -Check       environment check only
rem     run-gui.cmd -Install     install missing dependencies first
rem     run-gui.cmd -Headless    run the browser without a visible window
rem
rem It only forwards to run-gui.ps1 with -ExecutionPolicy Bypass, so it works
rem even when script execution is disabled by policy.
rem ---------------------------------------------------------------------------

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0run-gui.ps1" %*

if errorlevel 1 (
    echo.
    echo Something went wrong. Press any key to close this window.
    pause >nul
)
