# app.py - Shows Client's IP (LAN, VPN, Public)
from flask import Flask, render_template, Response, request
import json
import time
import os
import socket

app = Flask(__name__)
ALERT_FILE = "/home/grine/dos-idps/dashboard/alerts.json"
last_mtime = 0

def get_client_ip():
    if request.headers.get('X-Forwarded-For'):
        # For proxies / ngrok
        return request.headers.get('X-Forwarded-For').split(',')[0]
    elif request.remote_addr:
        return request.remote_addr
    else:
        return "Unknown"

def event_stream():
    global last_mtime
    while True:
        if os.path.exists(ALERT_FILE):
            try:
                mtime = os.path.getmtime(ALERT_FILE)
                if mtime > last_mtime:
                    with open(ALERT_FILE, 'r') as f:
                        alerts = json.load(f)
                    for alert in alerts:
                        yield f"data: {json.dumps(alert)}\n\n"
                    last_mtime = mtime
            except:
                pass
        time.sleep(1)

@app.route('/')
def index():
    client_ip = get_client_ip()
    return render_template('index.html', client_ip=client_ip)

@app.route('/stream')
def stream():
    return Response(event_stream(), mimetype="text/event-stream")

if __name__ == '__main__':
    print("DASHBOARD STARTED")
    print("   Access from LAN: http://192.168.1.107:5000")
    print("   Access via VPN:  http://100.90.3.86:5000")
    print("   Or use ngrok for public access")
    print("   Client will see their own IP on the page")
    app.run(host='0.0.0.0', port=5000, threaded=True)