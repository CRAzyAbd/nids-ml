# 🛡️ NIDS — Network Intrusion Detection System

A real-time Network Intrusion Detection System built with Python, Scapy, and scikit-learn.
Captures live network packets, extracts traffic features, and uses machine learning to detect anomalies and attacks.

> **Built as a cybersecurity portfolio project | VIT Bhopal — B.Tech Cyber Security & Digital Forensics**

---

## 🏗️ Project Phases

| Phase | Description | Status |
|-------|-------------|--------|
| 1 | Foundation — packet capture, logging, project structure | ✅ Complete |
| 2 | Feature Extraction — ML-ready feature engineering | 🔜 Upcoming |
| 3 | Dataset & Preprocessing — CICIDS2017 dataset | 🔜 Upcoming |
| 4 | ML Model Training — Random Forest + Isolation Forest | 🔜 Upcoming |
| 5 | Real-Time Detection — live model inference | 🔜 Upcoming |
| 6 | Dashboard — Flask web UI | 🔜 Upcoming |
| 7 | Polish — packaging, docs, demo | 🔜 Upcoming |

---

## ⚙️ Setup

### Prerequisites
- Ubuntu Linux
- Python 3.10+
- Root/sudo access (required for raw packet capture)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/nids-project.git
cd nids-project

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Configuration

Edit `config/settings.py` and set `INTERFACE` to your network interface name.

Find your interface with:
```bash
ip link show
```

---

## 🚀 Usage

```bash
# Basic capture (replace ens33 with your interface)
sudo python3 main.py

# Specify interface
sudo python3 main.py --interface wlan0

# Capture only TCP traffic
sudo python3 main.py --filter "tcp"

# Capture 500 packets then stop
sudo python3 main.py --count 500

# Combine options
sudo python3 main.py --interface eth0 --filter "port 80" --count 1000
```

---

## 📁 Project Structure

<pre>
nids-project/
├── config/settings.py      # All configuration constants
├── src/
│   ├── sniffer/
│   │   └── packet_capture.py  # Live packet sniffer (Scapy)
│   └── utils/
│       └── logger.py          # Colored logging utility
├── logs/                   # Runtime log files
├── captured_data/          # CSV files of captured packets
├── main.py                 # Entry point
└── requirements.txt
</pre>

---

## 🧰 Technologies

- **Scapy** — raw packet capture and protocol parsing
- **scikit-learn** — machine learning (Phase 4+)
- **pandas / numpy** — data manipulation (Phase 2+)
- **Flask** — web dashboard (Phase 6+)

