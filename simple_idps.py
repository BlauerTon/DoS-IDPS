#!/usr/bin/env python3
from scapy.all import *
import pandas as pd
import numpy as np
import joblib
from collections import defaultdict
import time
import json
import os
from datetime import datetime
import threading

class RealTimeIDPS:
    def __init__(self):
        self.INTERFACE = "wlan0"
        self.ML_MODEL_PATH = "udp_dos23.joblib"
        self.UDP_MONITOR_PORT = 12345
        self.ML_ALERT_THRESHOLD = 0.85
        self.UDP_FLOOD_THRESHOLD = 50
        self.FLOW_TIMEOUT = 5
        self.CLEANUP_INTERVAL = 2
        self.ALERTS_FILE = "alerts.json"

        # Statistics
        self.total_packets = 0
        self.total_alerts = 0
        self.start_time = time.time()
        self.packet_stats = {
            'udp': 0, 'tcp': 0, 'icmp': 0, 'other': 0
        }
        self.packet_rates = []
        self.known_services = {1900, 5353, 123, 53}

        # Network load tracking
        self.rate_history = []  # Store recent rates for load calculation
        self.max_observed_rate = 0

        # Debug counters
        self.udp_packets_count = 0
        self.last_debug_print = time.time()

        # Initialize data structures
        self.flows = defaultdict(list)
        self.udp_flows = defaultdict(list)
        self.last_cleanup = time.time()

        # ML model instance
        self.model = None

        # Load ML model
        self.ML_ENABLED = self.load_model()

        # Initialize alerts file
        self.init_alerts_file()

        # Feature definitions
        self.FEATURES = [
            'Header_Length', 'Protocol Type', 'Time_To_Live', 'Rate',
            'fin_flag_number', 'syn_flag_number', 'rst_flag_number', 'psh_flag_number',
            'ack_flag_number', 'ece_flag_number', 'cwr_flag_number', 'ack_count',
            'syn_count', 'fin_count', 'rst_count', 'HTTP', 'HTTPS', 'DNS', 'Telnet',
            'SMTP', 'SSH', 'IRC', 'TCP', 'UDP', 'DHCP', 'ARP', 'ICMP', 'IGMP',
            'IPv', 'LLC', 'Tot sum', 'Min', 'Max', 'AVG', 'Std', 'Tot size',
            'IAT', 'Number', 'Variance'
        ]

        print(f"Initialized IDPS - Monitoring port {self.UDP_MONITOR_PORT} with threshold {self.UDP_FLOOD_THRESHOLD} pps")

    def load_model(self):
        """Load ML model for attack detection"""
        try:
            self.model = joblib.load(self.ML_MODEL_PATH)
            print(f"ML Model loaded: expects {self.model.n_features_in_} features")
            return True
        except Exception as e:
            print(f"Warning: Could not load ML model: {e}")
            print("Continuing with threshold-based detection only")
            self.model = None
            return False

    def init_alerts_file(self):
        """Initialize alerts file"""
        if not os.path.exists(self.ALERTS_FILE):
            with open(self.ALERTS_FILE, 'w') as f:
                json.dump([], f)

    def save_alert(self, alert_data):
        """Save alert to JSON file"""
        try:
            with open(self.ALERTS_FILE, 'r') as f:
                try:
                    alerts = json.load(f)
                except json.JSONDecodeError:
                    alerts = []

            alert_data['timestamp'] = datetime.now().isoformat()
            alert_data['alert_id'] = f"alert_{int(time.time())}_{self.total_alerts}"
            self.total_alerts += 1

            alerts.append(alert_data)

            # Keep only last 100 alerts for dashboard performance
            if len(alerts) > 100:
                alerts = alerts[-100:]

            with open(self.ALERTS_FILE, 'w') as f:
                json.dump(alerts, f, indent=2)

            print(f"ALERT: {alert_data['type']} - {alert_data.get('packets_per_second', 0):.0f} pps from {alert_data.get('source_ip', 'Unknown')} to port {alert_data.get('destination_port', 'Unknown')}")

        except Exception as e:
            print(f"Error saving alert: {e}")

    def compute_features_fast(self, packets):
        """Fast feature computation for real-time detection"""
        if len(packets) < 2:
            return None

        times = [p.time for p in packets]
        sizes = [len(p) for p in packets]

        duration = max(times) - min(times)
        if duration < 0.001:
            duration = 0.001

        n = len(packets)
        rate = n / duration

        size_std = np.std(sizes) if n > 1 else 0
        avg_size = np.mean(sizes)

        has_udp = any(UDP in p for p in packets)
        has_tcp = any(TCP in p for p in packets)

        return {
            'Rate': rate, 'Number': n, 'Std': size_std, 'AVG': avg_size,
            'UDP': 1 if has_udp else 0, 'TCP': 1 if has_tcp else 0,
            'IAT': np.mean(np.diff(times)) if n > 1 else 0,
            'Variance': np.var(sizes) if n > 1 else 0
        }

    def update_packet_stats(self, pkt):
        """Update packet statistics for dashboard"""
        self.total_packets += 1

        # Track packet rate (last 10 seconds)
        current_time = time.time()
        self.packet_rates.append(current_time)
        # Remove rates older than 10 seconds
        self.packet_rates = [t for t in self.packet_rates if current_time - t <= 10]

        if UDP in pkt:
            self.packet_stats['udp'] += 1
            self.udp_packets_count += 1
        elif TCP in pkt:
            self.packet_stats['tcp'] += 1
        elif ICMP in pkt:
            self.packet_stats['icmp'] += 1
        else:
            self.packet_stats['other'] += 1

        # Debug output every 5 seconds
        if current_time - self.last_debug_print > 5:
            current_rate = len([t for t in self.packet_rates if current_time - t <= 5]) / 5
            print(f"DEBUG: Total packets: {self.total_packets}, UDP packets: {self.udp_packets_count}, Current rate: {current_rate:.1f} pps")
            self.last_debug_print = current_time

    def check_udp_flood(self, pkt):
        """Improved UDP flood detection with debugging"""
        if UDP in pkt:
            current_time = time.time()
            src_ip = pkt[IP].src
            dport = pkt[UDP].dport

            # Only monitor the specific port we care about
            if dport != self.UDP_MONITOR_PORT:
                return

            flow_key = (src_ip, dport)
            self.udp_flows[flow_key].append((current_time, len(pkt)))

            # Use sliding window of last 1 second for faster detection
            self.udp_flows[flow_key] = [p for p in self.udp_flows[flow_key]
                                      if p[0] > current_time - 1.0]

            current_flow_count = len(self.udp_flows[flow_key])

            # Analyze more frequently
            if current_flow_count >= 5:
                packets = self.udp_flows[flow_key]
                times = [p[0] for p in packets]

                duration = max(times) - min(times)
                if duration > 0:
                    rate = len(packets) / duration

                    # Update max observed rate for network load calculation
                    if rate > self.max_observed_rate:
                        self.max_observed_rate = rate

                    # Alert condition
                    if rate > self.UDP_FLOOD_THRESHOLD:
                        alert_data = {
                            'type': 'UDP_FLOOD',
                            'source_ip': src_ip,
                            'destination_port': dport,
                            'packets_per_second': round(rate, 1),
                            'packet_count': len(packets),
                            'duration_seconds': round(duration, 3),
                            'detection_method': 'THRESHOLD',
                            'severity': 'HIGH' if rate > 100 else 'MEDIUM',
                            'probability': 'N/A'
                        }

                        print(f"ATTACK DETECTED: {rate:.1f} pps from {src_ip} to port {dport}")
                        self.save_alert(alert_data)

                        # Reset this flow after detection to avoid continuous alerts
                        self.udp_flows[flow_key] = []

    def analyze_flow_ml(self, key, packets):
        """ML-based flow analysis with NaN fix"""
        if len(packets) < 5 or not self.ML_ENABLED or self.model is None:
            return

        # Skip ML analysis for known services
        if key[3] in self.known_services:
            return

        feats = self.compute_features_fast(packets)
        if not feats:
            return

        try:
            available_feats = {k: v for k, v in feats.items() if k in self.FEATURES}
            df = pd.DataFrame([available_feats])

            for feature in self.FEATURES:
                if feature not in df.columns:
                    df[feature] = 0

            df = df[self.FEATURES]
            df.replace([np.inf, -np.inf], np.nan, inplace=True)
            df.fillna(0, inplace=True)

            # Fix for NaN probability - ensure all values are finite
            if df.isnull().values.any():
                print("WARNING: NaN values in features, skipping ML prediction")
                return

            prob = self.model.predict_proba(df)[0][1]

            # Check if probability is valid
            if np.isnan(prob) or not np.isfinite(prob):
                print("WARNING: Invalid probability from ML model, skipping alert")
                return

            flow_id = f"{key[0]}->{key[1]}:{key[3]}"

            if prob > self.ML_ALERT_THRESHOLD:
                alert_data = {
                    'type': 'ML_DETECTION',
                    'flow_id': flow_id,
                    'probability': round(prob, 3),
                    'packet_rate': round(feats['Rate'], 1),
                    'packet_count': len(packets),
                    'protocol': 'UDP' if feats['UDP'] else 'TCP',
                    'source_ip': key[0],
                    'destination_ip': key[1],
                    'destination_port': key[3],
                    'detection_method': 'ML_MODEL',
                    'severity': 'CRITICAL' if prob > 0.95 else 'HIGH'
                }

                self.save_alert(alert_data)

        except Exception as e:
            print(f"ML prediction error: {e}")

    def cleanup_old_flows(self):
        """Clean up old flows"""
        current_time = time.time()

        # Clean main flows
        for key in list(self.flows.keys()):
            self.flows[key] = [p for p in self.flows[key] if p.time > current_time - self.FLOW_TIMEOUT]
            if not self.flows[key]:
                del self.flows[key]

        # Clean UDP flows
        for key in list(self.udp_flows.keys()):
            self.udp_flows[key] = [p for p in self.udp_flows[key] if p[0] > current_time - 3.0]
            if not self.udp_flows[key]:
                del self.udp_flows[key]

        self.last_cleanup = current_time

    def packet_handler(self, pkt):
        """Main packet handler"""
        if IP not in pkt:
            return

        # Update statistics
        self.update_packet_stats(pkt)

        # UDP flood detection
        self.check_udp_flood(pkt)

        # ML-based detection
        sport = pkt.sport if TCP in pkt or UDP in pkt else 0
        dport = pkt.dport if TCP in pkt or UDP in pkt else 0
        proto = pkt[IP].proto
        key = (pkt[IP].src, pkt[IP].dst, sport, dport, proto)

        self.flows[key].append(pkt)

        # ML analysis
        if len(self.flows[key]) >= 10:
            self.analyze_flow_ml(key, self.flows[key])

        # Periodic cleanup
        if time.time() - self.last_cleanup > self.CLEANUP_INTERVAL:
            self.cleanup_old_flows()

    def get_dashboard_stats(self):
        """Get statistics for dashboard with proper network load calculation"""
        uptime = time.time() - self.start_time
        current_time = time.time()

        # Calculate current packet rate (packets per second) - last 3 seconds for responsiveness
        recent_rates = [t for t in self.packet_rates if current_time - t <= 3]
        current_rate = len(recent_rates) / 3 if recent_rates else 0

        # Store rate history for dynamic max calculation
        self.rate_history.append(current_rate)
        # Keep only last 30 seconds of history
        self.rate_history = self.rate_history[-30:]

        # Dynamic network load calculation
        # Base: 1000 pps = 100% load, but adjust based on observed maximum
        base_max_rate = 1000
        dynamic_max = max(base_max_rate, self.max_observed_rate * 1.2)  # Add 20% buffer

        # Calculate network load with dynamic scaling
        network_load = min(100, (current_rate / dynamic_max) * 100)

        # If we're seeing high rates but load is low, scale it up
        if current_rate > 500 and network_load < 50:
            network_load = min(100, network_load * 2)

        alerts = []
        try:
            with open(self.ALERTS_FILE, 'r') as f:
                alerts = json.load(f)
        except:
            alerts = []

        # Attack detection logic
        recent_critical_alerts = [alert for alert in alerts[-5:]
                                if alert.get('severity') in ['HIGH', 'CRITICAL', 'MEDIUM']
                                and (current_time - datetime.fromisoformat(alert['timestamp']).timestamp()) < 30]

        return {
            'total_packets': self.total_packets,
            'total_alerts': self.total_alerts,
            'uptime_seconds': round(uptime, 1),
            'current_rate': round(current_rate, 1),
            'network_load': round(network_load, 1),
            'max_observed_rate': round(self.max_observed_rate, 1),
            'packet_stats': self.packet_stats,
            'recent_alerts': alerts[-10:],
            'system_status': 'UNDER_ATTACK' if len(recent_critical_alerts) > 0 else 'NORMAL'
        }

    def start_sniffing(self):
        """Start packet sniffing in a separate thread"""
        def sniff_thread():
            print(f"Starting packet capture on {self.INTERFACE}...")
            try:
                sniff(iface=self.INTERFACE, prn=self.packet_handler, filter="ip", store=0)
            except Exception as e:
                print(f"Packet capture error: {e}")

        thread = threading.Thread(target=sniff_thread, daemon=True)
        thread.start()
        print("IDPS monitoring started...")

def main_standalone():
    """Main function for standalone operation"""
    idps = RealTimeIDPS()

    print("REAL-TIME IDPS - STANDALONE MODE")
    print("=" * 50)
    if idps.ML_ENABLED:
        print(f"ML Detection: {idps.model.n_features_in_} features (threshold: {idps.ML_ALERT_THRESHOLD})")
    else:
        print("ML Detection: DISABLED - using threshold-based detection only")
    print(f"UDP Flood Detection: {idps.UDP_FLOOD_THRESHOLD}+ pps threshold")
    print(f"Target Port: {idps.UDP_MONITOR_PORT}")
    print(f"Alerts File: {idps.ALERTS_FILE}")
    print(f"Interface: {idps.INTERFACE}")
    print("=" * 50)
    print("Real-time monitoring with continuous alerts... (Ctrl+C to stop)")

    try:
        idps.start_sniffing()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nIDPS stopped by user")
        print(f"Total packets processed: {idps.total_packets}")
        print(f"Total alerts generated: {idps.total_alerts}")

if __name__ == "__main__":
    main_standalone()