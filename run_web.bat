@echo off
rem Starts the browser UI on http://127.0.0.1:8765/ (localhost only). Close this window to stop it.
rem Add --demo to try it with offline sample data.
cd /d "%~dp0"
python -m gcp_cis_audit --web %*
pause
