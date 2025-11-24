# SOHO-IDPS: DoS Attack Prevention in SOHO Networks

![Status](https://img.shields.io/badge/Status-Prototype-green?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Raspberry%20Pi-C51A4A?style=flat-square&logo=raspberry-pi&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=flat-square&logo=python&logoColor=white)
![Framework](https://img.shields.io/badge/Frontend-Flask%20%7C%20Tailwind-000000?style=flat-square)

A lightweight, machine learning-based Intrusion Detection and Prevention System (IDPS) designed for Small Office/Home Office (SOHO) networks. This system runs efficiently on edge devices (Raspberry Pi 4), utilizing a **Hybrid Detection Engine** (Random Forest + Rate Limiting) to detect and mitigate UDP/TCP floods in real-time.

---

##  Abstract
Small Office/Home Office (SOHO) networks are becoming increasingly popular targets for attackers, particularly via Denial of Service (DoS) attacks. Traditional IDS solutions are often too resource-intensive for the limited hardware found in these environments.

This project proposes a lightweight solution that offers a hybrid approach by applying signature-based rules and machine learning anomaly detection to identify known and emerging attack patterns. It features automated response mechanisms via `iptables` and a real-time web dashboard for network analytics.

---

##  Key Features

* **Hybrid Detection Logic:** Combines a Random Forest Classifier with traffic rate analysis to eliminate false positives from benign high-traffic apps.
* **Edge-Optimized:** Designed to run on Raspberry Pi 5 (8GB+ RAM) without exhausting CPU resources.
* **Real-Time Mitigation:** Automatically interacts with the Linux kernel firewall (`iptables`) to drop malicious packets instantly upon detection.
* **Industrial SIEM Dashboard:** A dark-mode, utilitarian web interface utilizing WebSockets for zero-latency updates on traffic stats and alerts.
* **Secure Authentication:** Built-in Login/Signup system with hashed credentials (Scrypt) and session management.
* **Live Traffic Analysis:** Uses `Scapy` to extract features (Entropy, Packet Size, Flags, IAT) in real-time.

---

##  System Architecture

The system follows a modular pipeline approach:

1.  **Ingress:** Traffic is captured via the wireless/ethernet interface (`wlan0`/`eth0`).
2.  **Preprocessing:** Packets are grouped into flows; statistical features are extracted every 2 seconds.
3.  **Inference:**
    * **Level 1:** Check against Allow/Block lists.
    * **Level 2:** Random Forest Model inference (trained on CICIoT23/UNSW-NB15).
    * **Level 3:** Logic Gate (Is Probability High? AND Is Rate High?).
4.  **Response:** If malicious, the IP is added to `iptables` DROP chain.
5.  **Visualization:** Events are pushed to the Flask Dashboard via Socket.IO.

---

##  Performance & Benchmarks

The Machine Learning model was trained and validated using the **UNSW-NB15** and **CICIoT23** datasets.

| Metric | Score | Description |
| :--- | :--- | :--- |
| **Accuracy** | **97%** | Overall classification accuracy on test data. |
| **Precision** | **0.95** | High precision ensures legitimate traffic is rarely blocked. |
| **Recall** | **0.98** | High recall ensures attacks are rarely missed. |
| **Live Confidence**| **~85%** | Average confidence observed during live LOIC UDP floods. |

---

##  Installation

### Prerequisites
* Raspberry Pi 5 (Recommended) or Linux VM.
* Python 3.8+.
* Root/Sudo privileges (Required for `scapy` sniffing and `iptables` manipulation).

### Setup Steps

1.  **Clone the Repository**
    ```bash
    git clone [https://github.com/yourusername/soho-idps.git](https://github.com/yourusername/soho-idps.git)
    cd soho-idps
    ```

2.  **Install Dependencies**
    ```bash
    pip3 install -r requirements.txt
    ```
    *Key requirements: `flask`, `flask_socketio`, `scapy`, `pandas`, `joblib`, `scikit-learn`, `flask_sqlalchemy`, `flask_login`.*

3.  **Database Initialization**
    The system uses SQLite. The database (`users.db`) will be created automatically on the first run.

4.  **Run the Application**
    **Note:** Must be run with `sudo` to access network interfaces.
    ```bash
    sudo python3 app.py
    ```

5.  **Access the Dashboard**
    Open your browser and navigate to: `http://<raspberry-pi-ip>:5000`

---

##  Usage Guide

### 1. Authentication
* On first launch, navigate to the **Sign Up** tab.
* Create an Admin account.
* Log in to access the dashboard.

### 2. Dashboard Monitoring
* **System Status:** Shows "MONITORING" (Blue) or "ATTACK DETECTED" (Red).
* **Live Log:** Displays categorized events (Normal flows, Warnings, Blocks).
* **Blocked IPs:** Lists currently mitigated IP addresses. IPs are automatically unblocked after 30 seconds (configurable).

### 3. Simulating an Attack (Testing)
To test the system, you can use a tool like **LOIC** or `hping3` from a separate machine on the network:
```bash
# Example UDP Flood using hping3
sudo hping3 --udp -p 80 --flood <raspberry-pi-ip>
