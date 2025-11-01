#!/usr/bin/env python3
from scapy.all import *
import pandas as pd
import numpy as np
import joblib
from collections import defaultdict
import time

# Load model
model = joblib.load("udp_dos23.joblib")
print(f"Model loaded: expects {model.n_features_in_} features")

FEATURES = [
    'Header_Length', 'Protocol Type', 'Time_To_Live',
    'Rate', 'fin_flag_number', 'syn_flag_number', 'rst_flag_number',
    'psh_flag_number', 'ack_flag_number', 'ece_flag_number', 'cwr_flag_number',
    'ack_count', 'syn_count', 'fin_count', 'rst_count',
    'HTTP', 'HTTPS', 'DNS', 'Telnet', 'SMTP', 'SSH', 'IRC',
    'TCP', 'UDP', 'DHCP', 'ARP', 'ICMP', 'IGMP', 'IPv', 'LLC',
    'Tot sum', 'Min', 'Max', 'AVG', 'Std', 'Tot size',
    'IAT', 'Number', 'Variance'
]

flows = defaultdict(list)
FLOW_TIMEOUT = 10
last_cleanup = time.time()
alerted_flows = set()

def compute_features(packets):
    if not packets: return None
    times = np.array([p.time for p in packets])
    sizes = np.array([len(p) for p in packets])
    duration = max(times) - min(times)
    if duration == 0: duration = 0.001
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
    tcp = 1 if any(TCP in p for p in packets) else 0
    udp = 1 if any(UDP in p for p in packets) else 0
    dhcp = 1 if any(UDP in p and p[UDP].dport in [67, 68] for p in packets) else 0
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

    return {
        'Header_Length': header_length, 'Protocol Type': proto, 'Time_To_Live': ttl,
        'Rate': rate, 'fin_flag_number': fin, 'syn_flag_number': syn, 'rst_flag_number': rst,
        'psh_flag_number': psh, 'ack_flag_number': ack, 'ece_flag_number': ece, 'cwr_flag_number': cwr,
        'ack_count': ack, 'syn_count': syn, 'fin_count': fin, 'rst_count': rst,
        'HTTP': http, 'HTTPS': https, 'DNS': dns, 'Telnet': telnet, 'SMTP': smtp, 'SSH': ssh, 'IRC': 0,
        'TCP': tcp, 'UDP': udp, 'DHCP': dhcp, 'ARP': arp, 'ICMP': icmp, 'IGMP': igmp, 'IPv': ipv, 'LLC': llc,
        'Tot sum': tot_sum, 'Min': min_len, 'Max': max_len, 'AVG': avg_len, 'Std': std_len, 'Tot size': tot_size,
        'IAT': iat_mean, 'Number': n, 'Variance': variance
    }

def packet_handler(pkt):
    global last_cleanup
    if IP not in pkt: return
    sport = pkt.sport if TCP in pkt or UDP in pkt else 0
    dport = pkt.dport if TCP in pkt or UDP in pkt else 0
    proto = pkt[IP].proto
    key = (pkt[IP].src, pkt[IP].dst, sport, dport, proto)
    flows[key].append(pkt)

    if time.time() - last_cleanup > 5:
        for k in list(flows):
            flows[k] = [p for p in flows[k] if p.time > time.time() - FLOW_TIMEOUT]
            if not flows[k]: del flows[k]
        last_cleanup = time.time()

    if len(flows[key]) >= 5 and (pkt.time - flows[key][0].time) > 1:
        feats = compute_features(flows[key])
        if feats:
            df = pd.DataFrame([feats])[FEATURES]
            df.replace([np.inf, -np.inf], np.nan, inplace=True)
            df.fillna(0, inplace=True)
            prob = model.predict_proba(df)[0][1]
            flow_id = f"{key[0]}→{key[1]}:{key[3]}"
            if prob > 0.7 and flow_id not in alerted_flows:
                print(f"ALERT: UDP FLOOD DETECTED | {flow_id} | Prob={prob:.3f} | Rate={feats['Rate']:.1f}/s | Pkts={len(flows[key])}")
                alerted_flows.add(flow_id)

print("Starting real-time IDS with YOUR 39 features...")
sniff(iface="wlan0", prn=packet_handler, filter="ip", store=0)