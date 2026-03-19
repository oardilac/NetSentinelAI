@echo off
title SentinelAI — Flow-Based Network Security Monitor
echo =====================================================
echo   SentinelAI - Flow-Based Network Security Monitor
echo =====================================================
echo.
echo   IMPORTANT: This script must be run as Administrator
echo   (Right-click -^> Run as administrator)
echo.
echo   Installing dependencies...
pip install -r requirements.txt --quiet
echo.
echo   Starting server on http://localhost:5050
echo   Press Ctrl+C to stop
echo.
python dashboard_server.py
pause
