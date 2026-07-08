@echo off
:loop
echo Starting FastAPI Backend...
call .\venv\Scripts\uvicorn backend.main:app --host 0.0.0.0 --port 8000
echo Backend crashed, restarting in 2 seconds...
timeout /t 2 /nobreak >nul
goto loop
