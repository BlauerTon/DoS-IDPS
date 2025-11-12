#!/usr/bin/env python3
from flask import Flask, render_template, jsonify, request
import json
import time
from datetime import datetime
from simple_idps import RealTimeIDPS
import threading

app = Flask(__name__)

# Initialize IDPS
idps_system = RealTimeIDPS()

@app.route('/')
def dashboard():
    """Main dashboard page"""
    stats = idps_system.get_dashboard_stats()
    return render_template('index.html',
                         stats=stats,
                         dashboard_ip="100.90.3.86",
                         dashboard_port=5000)

@app.route('/api/stats')
def get_stats():
    """API endpoint for real-time statistics"""
    stats = idps_system.get_dashboard_stats()
    return jsonify(stats)

@app.route('/api/alerts')
def get_alerts():
    """API endpoint for recent alerts"""
    try:
        with open('alerts.json', 'r') as f:
            alerts = json.load(f)
        return jsonify(alerts[-20:])
    except:
        return jsonify([])

@app.route('/api/clear_alerts', methods=['POST'])
def clear_alerts():
    """Clear all alerts"""
    try:
        with open('alerts.json', 'w') as f:
            json.dump([], f)
        idps_system.total_alerts = 0
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

if __name__ == '__main__':
    # Start IDPS monitoring in background
    idps_system.start_sniffing()

    print("Starting IDPS Dashboard...")
    print(f"Dashboard URL: http://100.90.3.86:5000")
    print(f"Network Interface: {idps_system.INTERFACE}")
    print(f"Monitoring started on port {idps_system.UDP_MONITOR_PORT}")

    # Run Flask app
    app.run(host='100.90.3.86', port=5000, debug=True)