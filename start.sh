#!/bin/bash
cd backend
source venv/Scripts/activate
while true; do
    python -m uvicorn main:app --host 127.0.0.1 --port 8000
    echo "Backend crashed. Restarting in 2s..."
    sleep 2
done
