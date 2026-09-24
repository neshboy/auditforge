@echo off
REM One-click launcher for AuditForge on Windows (cmd.exe wrapper).
REM Forwards all arguments to Run-AuditForge.ps1 and preserves the exit code.
setlocal
set SCRIPT_DIR=%~dp0
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%Run-AuditForge.ps1" %*
exit /b %ERRORLEVEL%
