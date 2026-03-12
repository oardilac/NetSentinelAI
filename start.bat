@echo off
REM Network Security Monitor - Inicio Rapido
REM Ejecutar como Administrador

title Network Security Monitor

echo ============================================================
echo    NETWORK SECURITY MONITOR - Dashboard de Seguridad
echo ============================================================
echo.

REM Verificar privilegios de administrador
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Este script requiere privilegios de Administrador
    echo.
    echo Por favor:
    echo 1. Click derecho en este archivo
    echo 2. Seleccionar "Ejecutar como administrador"
    echo.
    pause
    exit /b 1
)

echo [OK] Ejecutando como Administrador
echo.

REM Verificar Python
py --version >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Python no esta instalado o no esta en PATH
    echo.
    echo Descargar desde: https://www.python.org/downloads/
    echo.
    pause
    exit /b 1
)

echo [OK] Python detectado
echo.

REM Verificar dependencias
echo Verificando dependencias...
py -3.11 -c "import scapy" >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] Instalando dependencias...
    pip install -r requirements.txt
    if %errorLevel% neq 0 (
        echo [ERROR] Error al instalar dependencias
        pause
        exit /b 1
    )
) else (
    echo [OK] Dependencias instaladas
)
echo.

REM Verificar Npcap
py -3.11 -c "from scapy.all import get_if_list; get_if_list()" >nul 2>&1
if %errorLevel% neq 0 (
    echo [ADVERTENCIA] Npcap no detectado o no funciona correctamente
    echo.
    echo Descargar desde: https://npcap.com/
    echo IMPORTANTE: Instalar en modo WinPcap compatible
    echo.
    pause
)

REM Obtener IP local
echo ============================================================
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /c:"IPv4"') do (
    set IP=%%a
    goto :found
)
:found
set IP=%IP:~1%

echo Dashboard estara disponible en:
echo.
echo   Local:  http://localhost:5050
echo   Red:    http://%IP%:5050
echo.
echo ============================================================
echo.
echo Iniciando servidor...
echo Presiona Ctrl+C para detener
echo.

REM Iniciar servidor
py -3.11 "C:\Users\Usuario\Downloads\Sniffer\dashboard_server.py"

pause
