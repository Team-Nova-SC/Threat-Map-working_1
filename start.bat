@echo off
cd backend
call venv\Scripts\activate.bat
:loop
python -m uvicorn main:app --host 127.0.0.1 --port 8000
echo Backend crashed. Restarting in 2s...
timeout /t 2 /nobreak
goto loop
