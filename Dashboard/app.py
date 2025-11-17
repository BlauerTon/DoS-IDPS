#!/usr/bin/env python3
import os
import sys
import time
import joblib
import pandas as pd
import numpy as np
from collections import defaultdict
from scapy.all import *
import threading
import subprocess

from flask import Flask, render_template
from flask_socketio import SocketIO, emit

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this'
socketio = SocketIO(app, async_mode='threading')

MODEL_NAME = "udp_dos23.joblib"
INTERFACE = "wlan0"

SAFE_IPS = {
    "127.0.0.1",
    "192.168.100.9"
}

FLOW_TIMEOUT = 10
ANALYSIS_INTERVAL = 2
ALERT_THRESHOLD = 0.70
PACKET_MIN_FOR_ANALYSIS = 20
BLOCK_DURATION = 30
WARNING_THRESHOLD_COUNT = 5
BLOCK_THRESHOLD_COUNT = 8

flows = {}
flows_lock = threading.Lock()

blocked_ips = set()
blocked_ips_lock = threading.Lock()  # lock for blocked_ips modifications

model = None
FEATURES = []

global_packet_count = 0
global_byte_count = 0
global_stats_lock = threading.Lock()


def read_iptables_blocked_ips():
    """
    Return a list of source IPs from iptables INPUT chain that have target DROP.
    """
    try:
        cmd = ["iptables", "-L", "INPUT", "-n", "--line-numbers"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        lines = result.stdout.splitlines()
    except Exception as e:
        print(f"Error reading iptables: {e}")
        return []

    found = []
    for line in lines:
        parts = line.split()
        if len(parts) < 5:
            continue
        # typical line: num  target  prot opt source destination
        # parts[1] == "DROP", parts[4] == source
        if parts[1] == "DROP":
            found.append(parts[4])
    return found


def sync_blocked_ips_from_iptables():
    """
    Replace the in-memory blocked_ips set with the current iptables DROP entries.

    This makes the dashboard reflect the real firewall state even if rules were added
    or removed outside this script.
    """
    iptables_list = read_iptables_blocked_ips()
    with blocked_ips_lock:
        # replace in-memory set with iptables set
        blocked_ips.clear()
        blocked_ips.update(iptables_list)


class Flow:
    def __init__(self, key):
        self.key = key
        self.packets = []
        self.alerted = False
        self.detection_count = 0

    def add_packet(self, pkt):
        self.packets.append(pkt)

    def prune(self):
        now = time.time()
        self.packets = [p for p in self.packets if now - p.time < FLOW_TIMEOUT]

    def compute_features(self):
        packets = self.packets
        if not packets:
            return None

        times = np.array([p.time for p in packets])
        sizes = np.array([len(p) for p in packets])

        duration = max(times) - min(times)
        if duration == 0:
            duration = 0.001

        n = len(packets)
        ttl_list = [p[IP].ttl if IP in p else 64 for p in packets]
        ip_hdr_lens = [p[IP].ihl * 4 if IP in p else 20 for p in packets]
        proto = packets[0][IP].proto if IP in packets[0] else 17

        header_length = sum(ip_hdr_lens)
        ttl = np.mean(ttl_list)

        fin = syn = rst = psh = ack = ece = cwr = 0
        for p in packets:
            if TCP in p:
                f = p[TCP].flags
                fin += (f & 0x01) > 0
                syn += (f & 0x02) > 0
                rst += (f & 0x04) > 0
                psh += (f & 0x08) > 0
                ack += (f & 0x10) > 0
                ece += (f & 0x40) > 0
                cwr += (f & 0x80) > 0

        http = 1 if any(Raw in p and b'HTTP' in p[Raw].load for p in packets) else 0
        https = 1 if any(TCP in p and p[TCP].dport in [443, 8443] for p in packets) else 0
        dns = 1 if any(UDP in p and p[UDP].dport == 53 for p in packets) else 0
        telnet = 1 if any(TCP in p and p[TCP].dport == 23 for p in packets) else 0
        smtp = 1 if any(TCP in p and p[TCP].dport == 25 for p in packets) else 0
        ssh = 1 if any(TCP in p and p[TCP].dport == 22 for p in packets) else 0
        dhcp = 1 if any(UDP in p and p[UDP].dport in [67, 68] for p in packets) else 0

        tcp = 1 if any(TCP in p for p in packets) else 0
        udp = 1 if any(UDP in p for p in packets) else 0
        arp = 1 if any(ARP in p for p in packets) else 0
        icmp = 1 if any(ICMP in p for p in packets) else 0
        igmp = 1 if proto == 2 else 0
        ipv = 1
        llc = 0

        rate = n / duration
        tot_sum = sizes.sum()
        min_len = sizes.min()
        max_len = sizes.max()
        avg_len = sizes.mean()
        std_len = sizes.std() if n > 1 else 0

        tot_size = tot_sum
        iat = np.diff(times) if n > 1 else np.array([0])
        iat_mean = iat.mean()
        variance = sizes.var() if n > 1 else 0

        feature_dict = {
            'Header_Length': header_length,
            'Protocol Type': proto,
            'Time_To_Live': ttl,
            'Rate': rate,
            'fin_flag_number': fin,
            'syn_flag_number': syn,
            'rst_flag_number': rst,
            'psh_flag_number': psh,
            'ack_flag_number': ack,
            'ece_flag_number': ece,
            'cwr_flag_number': cwr,
            'ack_count': ack,
            'syn_count': syn,
            'fin_count': fin,
            'rst_count': rst,
            'HTTP': http,
            'HTTPS': https,
            'DNS': dns,
            'Telnet': telnet,
            'SMTP': smtp,
            'SSH': ssh,
            'IRC': 0,
            'TCP': tcp,
            'UDP': udp,
            'DHCP': dhcp,
            'ARP': arp,
            'ICMP': icmp,
            'IGMP': igmp,
            'IPv': ipv,
            'LLC': llc,
            'Tot sum': tot_sum,
            'Min': min_len,
            'Max': max_len,
            'AVG': avg_len,
            'Std': std_len,
            'Tot size': tot_size,
            'IAT': iat_mean,
            'Number': n,
            'Variance': variance
        }

        return pd.DataFrame([feature_dict], columns=FEATURES)


def packet_handler(pkt):
    global global_packet_count, global_byte_count

    with global_stats_lock:
        global_packet_count += 1
        global_byte_count += len(pkt)

    if IP not in pkt:
        return

    src_ip = pkt[IP].src

    with blocked_ips_lock:
        if src_ip in blocked_ips:
            return

    if src_ip in SAFE_IPS:
        return

    sport = pkt.sport if TCP in pkt or UDP in pkt else 0
    dport = pkt.dport if TCP in pkt or UDP in pkt else 0
    proto = pkt[IP].proto

    key = (src_ip, pkt[IP].dst, sport, dport, proto)

    with flows_lock:
        if key not in flows:
            flows[key] = Flow(key)
        flows[key].add_packet(pkt)


def unblock_ip_after_delay(ip_address, delay_seconds):
    print(f"Unblocking {ip_address} in {delay_seconds} seconds...")
    socketio.emit('system_message', {'msg': f"Unblocking {ip_address} in {delay_seconds}s..."})
    time.sleep(delay_seconds)

    # attempt to remove rule from iptables and update in-memory set
    try:
        ret = os.system(f"iptables -D INPUT -s {ip_address} -j DROP")
    except Exception as e:
        print(f"Error removing iptables rule for {ip_address}: {e}")
        ret = 1

    with blocked_ips_lock:
        if ip_address in blocked_ips:
            blocked_ips.discard(ip_address)
            print(f"TIMER: Unblocked {ip_address} and removed from in-memory set")
        else:
            # even if not in the set, ensure we reflect what iptables actual state is
            print(f"TIMER: {ip_address} was not present in in-memory set")

    # Clean up flows for that IP
    with flows_lock:
        for key in list(flows.keys()):
            if key[0] == ip_address:
                del flows[key]
                print(f"Clearing flow {key}")


def block_ip(ip_address):
    with blocked_ips_lock:
        if ip_address not in blocked_ips:
            print(f"MITIGATING: Blocking IP {ip_address} for {BLOCK_DURATION}s")
            os.system(f"iptables -I INPUT 1 -s {ip_address} -j DROP")
            blocked_ips.add(ip_address)

            socketio.emit('system_message', {'msg': f"IP {ip_address} BLOCKED for {BLOCK_DURATION}s"})

            unblock_thread = threading.Thread(
                target=unblock_ip_after_delay,
                args=(ip_address, BLOCK_DURATION)
            )
            unblock_thread.daemon = True
            unblock_thread.start()


def analysis_loop():
    global model, FEATURES

    # wait for model
    while model is None:
        print("Analysis loop waiting for model to load...")
        time.sleep(1)

    print("Analysis loop started.")

    while True:
        time.sleep(ANALYSIS_INTERVAL)

        with global_stats_lock:
            global global_packet_count, global_byte_count
            pps = global_packet_count / ANALYSIS_INTERVAL
            bps = global_byte_count / ANALYSIS_INTERVAL
            global_packet_count = 0
            global_byte_count = 0

        with flows_lock:
            active_flow_keys = list(flows.keys())

        # sync blocked IPs from iptables so dashboard is accurate
        sync_blocked_ips_from_iptables()

        with blocked_ips_lock:
            current_blocked = list(blocked_ips)

        socketio.emit('update_stats', {
            'active_flows': len(active_flow_keys),
            'blocked_ips_list': current_blocked,
            'pps': pps,
            'bps': bps
        })

        if not active_flow_keys:
            continue

        for key in active_flow_keys:
            src_ip, dst_ip, sport, dport = key[0], key[1], key[2], key[3]

            if src_ip in SAFE_IPS:
                with flows_lock:
                    if key in flows:
                        del flows[key]
                continue

            with flows_lock:
                if key not in flows:
                    continue
                flow = flows[key]
                flow.prune()
                if not flow.packets:
                    del flows[key]
                    continue
                if len(flow.packets) < PACKET_MIN_FOR_ANALYSIS:
                    continue
                df = flow.compute_features()

            if df is None:
                continue

            df.replace([np.inf, -np.inf], np.nan, inplace=True)
            df.fillna(0, inplace=True)

            prob_benign = model.predict_proba(df)[0][0]
            prob_attack = 1.0 - prob_benign

            flow_id = f"{src_ip}:{sport} -> {dst_ip}:{dport}"

            if prob_attack > ALERT_THRESHOLD:
                print(f"ATTACK | {flow_id} | Prob={prob_attack:.3f}")
                socketio.emit('system_message', {
                    'msg': f"Suspicious traffic from {src_ip} | Prob={prob_attack:.3f}"
                })

                with flows_lock:
                    if key not in flows:
                        continue
                    flow.detection_count += 1
                    count = flow.detection_count

                    if not flow.alerted:
                        if count == WARNING_THRESHOLD_COUNT:
                            msg = f"Potential attack from {src_ip}"
                            print(msg)
                            socketio.emit('system_message', {'msg': msg})

                            alert_data = {
                                'flow_id': flow_id,
                                'prob_attack': f"{prob_attack:.3f}",
                                'rate': f"{df['Rate'].iloc[0]:.1f}",
                                'packets': f"{df['Number'].iloc[0]}"
                            }
                            socketio.emit('new_alert', alert_data)

                        elif count >= BLOCK_THRESHOLD_COUNT:
                            msg = f"Continuous traffic flood from {src_ip}. Blocking."
                            print(msg)
                            block_ip(src_ip)
                            flow.alerted = True

            else:
                with flows_lock:
                    if key in flows:
                        if flow.detection_count > 0:
                            flow.detection_count = max(0, flow.detection_count - 1)
                            print(f"FLOW NORMAL (Count: {flow.detection_count}) | {flow_id}")

                            if flow.detection_count == 0:
                                socketio.emit('flow_normal', {'flow_id': flow_id})
                                flow.alerted = False


def start_sniffer():
    print(f"Starting sniffer on interface {INTERFACE}...")
    try:
        sniff(iface=INTERFACE, prn=packet_handler, filter="ip", store=0)
    except Exception as e:
        print(f"An error occurred in the sniffer thread: {e}")


@app.route('/')
def index():
    return render_template('index.html')


@socketio.on('connect')
def handle_connect():
    print('Client connected to dashboard')
    # sync once on client connect so UI sees current firewall state
    sync_blocked_ips_from_iptables()
    with blocked_ips_lock:
        socketio.emit('update_stats', {
            'active_flows': len(flows),
            'blocked_ips_list': list(blocked_ips),
            'pps': 0,
            'bps': 0
        })


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Error: This script must be run as root (sudo).")
        sys.exit(1)

    print("Loading model...")
    try:
        model = joblib.load(MODEL_NAME)
        FEATURES = model.feature_names_in_
        print(f"Model '{MODEL_NAME}' loaded.")
    except FileNotFoundError:
        print(f"Error: Could not find model file '{MODEL_NAME}'.")
        sys.exit(1)
    except Exception as e:
        print(f"Error loading model: {e}")
        sys.exit(1)

    # initial sync of blocked IPs from iptables
    sync_blocked_ips_from_iptables()

    print("Starting analysis thread...")
    analyzer_thread = threading.Thread(target=analysis_loop, daemon=True)
    analyzer_thread.start()

    print("Starting sniffer thread...")
    sniffer_thread = threading.Thread(target=start_sniffer, daemon=True)
    sniffer_thread.start()

    print("IDPS Dashboard starting on http://100.90.3.86:5000")
    socketio.run(app, host='100.90.3.86', port=5000, allow_unsafe_werkzeug=True, debug=False)
