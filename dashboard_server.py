#!/usr/bin/env python3
"""
Dashboard Web Server - Servidor Flask para el dashboard de métricas
"""

from flask import Flask, render_template, jsonify, send_from_directory
from flask_cors import CORS
from threading import Thread
import network_monitor
import os
import sys

app = Flask(__name__)
CORS(app)

# Variable global para el sniffer
sniffer_thread = None

@app.route('/')
def index():
    """Página principal del dashboard"""
    return send_from_directory('./', 'dashboard.html')

@app.route('/api/metrics')
def get_metrics():
    """API endpoint para obtener métricas en tiempo real"""
    sniffer = network_monitor.get_sniffer()
    metrics = sniffer.metrics.get_metrics()
    return jsonify(metrics)

@app.route('/api/start')
def start_monitoring():
    """Inicia el monitoreo de red"""
    global sniffer_thread
    
    if sniffer_thread is not None and sniffer_thread.is_alive():
        return jsonify({'status': 'already_running', 'message': 'Monitoreo ya está activo'})
    
    sniffer = network_monitor.get_sniffer()
    sniffer_thread = Thread(target=sniffer.start_sniffing, daemon=True)
    sniffer_thread.start()
    
    return jsonify({'status': 'started', 'message': 'Monitoreo iniciado'})

@app.route('/api/stop')
def stop_monitoring():
    """Detiene el monitoreo de red"""
    sniffer = network_monitor.get_sniffer()
    sniffer.stop_sniffing()
    return jsonify({'status': 'stopped', 'message': 'Monitoreo detenido'})

@app.route('/api/status')
def get_status():
    """Retorna el estado del monitoreo"""
    sniffer = network_monitor.get_sniffer()
    return jsonify({
        'running': sniffer.running,
        'interface': sniffer.interface or 'all'
    })

def main():
    """Inicia el servidor web"""
    print("="*70)
    print("NETWORK SECURITY MONITOR - Dashboard Web")
    print("="*70)
    print()
    print("IMPORTANTE: Ejecutar como Administrador en Windows")
    print("            (Click derecho -> Ejecutar como administrador)")
    print()
    print("El dashboard estará disponible en: http://localhost:5050")
    print()
    print("Presiona Ctrl+C para detener el servidor")
    print("="*70)
    print()
    
    # Crear directorio static si no existe
    if not os.path.exists('static'):
        os.makedirs('static')
    
    # Iniciar servidor
    try:
        app.run(host='0.0.0.0', port=5050, debug=False, threaded=True)
    except KeyboardInterrupt:
        print("\n[!] Servidor detenido")
        sys.exit(0)

if __name__ == '__main__':
    main()
