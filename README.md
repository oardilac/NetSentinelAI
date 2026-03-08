# 🛡️ PySentry

<!-- Dynamic Typing Animation -->
<p align="center">
  <img src="https://readme-typing-svg.demolab.com?font=Share+Tech+Mono&weight=600&size=40&pause=1000&color=00FF41&center=true&vCenter=true&width=800&lines=Welcome+to+PySentry+By+Bismaya;Real-Time+Intrusion+Detection;Powered+by+Machine+Learning;Stay+Secure.+Stay+Vigilant." alt="Animated PySentry Intro" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/Streamlit-PySentry_UI-red?style=for-the-badge&logo=streamlit&logoColor=white" />
  <img src="https://img.shields.io/badge/Status-Actively_Monitoring-00ff41?style=for-the-badge" />
</p>

A hybrid Intrusion Detection System (IDS). 

**PySentry** listens to the invisible data flowing through your computer's network card, parses network flows, looks for known bad behavior (signatures), and uses machine learning (`IsolationForest`) to spot weird, unknown anomalous behavior in real time.

---

## 🟢 Features
- **Real-Time Packet Sniffing:** Powered by `scapy`.
- **Signature Detection:** Checks against strict hardcoded rules to catch known attacks (SYN Floods & Port Scans).
- **AI Anomaly Detection:** Uses `scikit-learn` to establish baseline network metrics and automatically alert on sudden spikes.
- **Operations Dashboard:** A Streamlit interface for live interactive monitoring.
- **Instant Report Generation:** One-click generation of formatted threat reports that copy directly to your clipboard or download as PNGs.

---

## 💻 Quick Start

### 1. Installation
Install the necessary packages via the updated requirements file:
```bash
pip install -r requirements.txt
```

### 2. Start the Engine
Run the primary detection engine. *(Note: Packet sniffing usually requires Administrator/root privileges!)*
```bash
python main.py
```

### 3. Open the Monitor (Dashboard)
In a secondary terminal, spin up the Hacker Dashboard:
```bash
streamlit run dashboard.py
```
