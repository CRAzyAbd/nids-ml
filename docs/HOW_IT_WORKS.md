# How This Project Works — Complete Beginner's Guide

This document explains every concept in this project from absolute basics.
No prior knowledge assumed.

---

## Table of Contents

1. [What Problem Are We Solving?](#1-what-problem-are-we-solving)
2. [What is a Network Packet?](#2-what-is-a-network-packet)
3. [What is Scapy?](#3-what-is-scapy)
4. [What is a Network Flow?](#4-what-is-a-network-flow)
5. [What are Features?](#5-what-are-features)
6. [What is the CICIDS-2017 Dataset?](#6-what-is-the-cicids-2017-dataset)
7. [What is Machine Learning?](#7-what-is-machine-learning)
8. [What is a Random Forest?](#8-what-is-a-random-forest)
9. [What is an Isolation Forest?](#9-what-is-an-isolation-forest)
10. [What is StandardScaler?](#10-what-is-standardscaler)
11. [What is Flask and SocketIO?](#11-what-is-flask-and-socketio)
12. [How the Whole System Works Together](#12-how-the-whole-system-works-together)
13. [How to Run the Project](#13-how-to-run-the-project)
14. [Understanding the Dashboard](#14-understanding-the-dashboard)
15. [Understanding the Alerts](#15-understanding-the-alerts)
16. [Common Terms Glossary](#16-common-terms-glossary)

---

## 1. What Problem Are We Solving?

Imagine your home has a security guard at the door. Every person who
enters gets checked. If someone looks suspicious — wrong ID, weird
behaviour, trying to pick the lock — the guard raises an alarm.

A **Network Intrusion Detection System (NIDS)** is that security guard,
but for computer networks. Instead of watching people, it watches
**network traffic** — all the data flowing in and out of a computer
or network.

Every time you open a website, send an email, or use an app, your
computer sends and receives small chunks of data called **packets**.
Attackers also send packets — but their packets follow different
patterns. A port scanner sends thousands of tiny packets to many
different ports very quickly. A DoS attacker sends an overwhelming
flood of packets to crash a server.

Our NIDS watches all these packets, learns what normal traffic looks
like, and flags anything suspicious.

---

## 2. What is a Network Packet?

When you visit a website, your browser doesn't send one giant message.
It breaks the request into small chunks called **packets**, sends them
across the internet, and they get reassembled at the other end.

Think of it like sending a large book by mail — you tear it into 100
envelopes and send them separately. Each envelope (packet) has:

- **A to address** (destination IP + port)
- **A from address** (source IP + port)
- **The content** (a chunk of the actual data)
- **Metadata** (how many more envelopes are coming, whether this
  arrived correctly, etc.)

### What is an IP address?

An IP address is like a home address for a computer.
Example: `192.168.1.5` is your computer on your home network.
`8.8.8.8` is Google's DNS server.

### What is a Port?

A port is like an apartment number within a building.
The building is the computer (IP address), the apartment is the
specific program (port number).

Common ports:
- Port 80 → HTTP (websites)
- Port 443 → HTTPS (secure websites)
- Port 22 → SSH (remote terminal)
- Port 53 → DNS (domain name lookup)

### What are Protocols?

A protocol is a set of rules for how computers talk to each other.

- **TCP** (Transmission Control Protocol) — reliable, ordered delivery.
  Used for websites, file downloads. Has a "handshake" (SYN, ACK, FIN flags).
- **UDP** (User Datagram Protocol) — fast but unreliable. Used for DNS,
  video calls, games.
- **ICMP** — used for network diagnostics. `ping` uses ICMP.

### What are TCP Flags?

TCP packets carry flags — small on/off signals that indicate what the
packet is doing:

- **SYN** — "I want to start a connection"
- **ACK** — "I received your packet"
- **FIN** — "I want to close the connection"
- **RST** — "Connection rejected / aborted immediately"
- **PSH** — "Send this data to the application right away"

Port scans send only SYN packets (no ACK, no FIN) — that's how we
detect them. A normal connection has SYN → SYN-ACK → ACK → data → FIN.

---

## 3. What is Scapy?

Scapy is a Python library that can read raw network packets directly
from your network interface — before your operating system has processed
them. It operates at a very low level.

Normally, when you use Python's `requests` library to visit a website,
the OS handles all the packet details for you. Scapy bypasses all of
that and gives you access to every single byte of every packet.

This is why the sniffer needs **root/sudo** access — reading raw packets
is a privileged operation in Linux (and every OS). Regular programs
can't do it for security reasons.

In our code (`src/sniffer/packet_capture.py`), we use Scapy's `sniff()`
function:

```python
sniff(
    iface="wlo1",      # which network interface to listen on
    prn=callback,      # function to call for every packet
    store=False,       # don't store packets in RAM (we handle storage)
)
```

For each packet, we check what layers it has:

```python
if packet.haslayer(TCP):
    src_port = packet[TCP].sport   # source port
    dst_port = packet[TCP].dport   # destination port
    flags    = packet[TCP].flags   # SYN, ACK, FIN, etc.
```

---

## 4. What is a Network Flow?

A single packet by itself tells you very little.
A **flow** is the complete conversation between two computers.

### The 5-Tuple

Every flow is identified by 5 pieces of information (the "5-tuple"):

1. Source IP address
2. Source port
3. Destination IP address
4. Destination port
5. Protocol (TCP, UDP, ICMP)

Example: When you visit GitHub, a flow might look like:

(192.168.1.5, 54321) → (140.82.113.3, 443) via TCP

All packets that share these 5 values belong to the same flow —
they're part of the same conversation.

### Why Flows Matter

Statistics computed over an entire flow reveal attack patterns that
individual packets cannot:

| Attack | Flow Pattern |
|--------|-------------|
| Port Scan | Many flows, each to different dst_port, all tiny (1-3 packets) |
| DoS | One flow, millions of packets, enormous bytes/sec |
| Brute Force | Many flows to same dst_port (22=SSH), all RST terminated |
| Normal Web | Moderate size, mix of flags, consistent timing |

### Flow Tracking in Our Code

`src/features/flow_tracker.py` maintains a dictionary of active flows.
For every incoming packet:

1. Extract the 5-tuple
2. Look it up in the dictionary (check both directions — A→B and B→A
   belong to the same flow)
3. If found, add the packet to that flow
4. If not found, create a new flow entry
5. When the flow ends (TCP FIN/RST) or times out (no packets for 120s),
   compute features and export

---

## 5. What are Features?

A feature is a number that describes something measurable.

Machine learning models don't understand "this packet looks suspicious".
They only understand numbers. So we convert network flows into a list
of 36 numbers (features) that capture the flow's statistical properties.

### Our 36 Features Explained

**Volume features** — how much data was transferred:
- `total_fwd_packets` — packets from initiator to responder
- `total_bwd_packets` — packets from responder to initiator
- `total_fwd_bytes` — bytes going forward
- `total_bwd_bytes` — bytes going backward
- `total_bytes` — total bytes in the flow

**Rate features** — how fast:
- `bytes_per_sec` — bytes per second (DoS = extremely high)
- `pkts_per_sec` — packets per second

**Timing features** — the rhythm of the conversation:
- `duration` — how long the flow lasted in seconds

**Inter-Arrival Time (IAT)** — the gap between consecutive packets.
This is one of the most powerful features. Humans browsing the web
have irregular, human-paced timing. Automated attack tools send
packets at machine speed with very uniform, tiny gaps.
- `flow_iat_mean` — average gap between any two consecutive packets
- `flow_iat_std` — standard deviation (how irregular the timing is)
- `fwd_iat_mean`, `fwd_iat_std`, `fwd_iat_max`, `fwd_iat_min`
- `bwd_iat_mean`, `bwd_iat_std`, `bwd_iat_max`, `bwd_iat_min`

**Packet length statistics** — the size distribution of packets:
- `fwd_pkt_len_mean`, `fwd_pkt_len_std`, `fwd_pkt_len_max`, `fwd_pkt_len_min`
- `bwd_pkt_len_mean`, `bwd_pkt_len_std`, `bwd_pkt_len_max`, `bwd_pkt_len_min`
- `avg_pkt_len`, `std_pkt_len`

Port scans use tiny packets (just a TCP header, no data).
File transfers use maximum-size packets (1460 bytes each).

**TCP Flag counts** — how many packets had each flag:
- `syn_count`, `ack_count`, `fin_count`, `rst_count`, `psh_count`, `urg_count`

**Byte direction ratio**:
- `bwd_fwd_byte_ratio` — ratio of backward to forward bytes.
  Normal web browsing: you send a small request, get a large response
  (ratio >> 1). Data exfiltration: you send a lot out (ratio << 1).

### How Features Are Computed

`src/features/feature_extractor.py` takes a completed `Flow` object
and returns a dictionary of these 36 numbers:

```python
features = extract_features(flow)
# Returns:
# {
#   "duration": 4.23,
#   "total_fwd_packets": 8,
#   "bytes_per_sec": 1205.4,
#   "syn_count": 1,
#   "flow_iat_mean": 0.523,
#   ... (36 features total)
# }
```

---

## 6. What is the CICIDS-2017 Dataset?

The **Canadian Institute for Cybersecurity Intrusion Detection System
2017** dataset is the gold standard for NIDS research.

Researchers at the University of New Brunswick set up a real network,
generated realistic normal traffic for a week (web browsing, email,
file transfers, video streaming), and then launched real attacks —
port scans, DoS floods, DDoS, brute force, web attacks, botnets.

They captured everything using their own flow extractor (CICFlowMeter)
and labeled every flow: BENIGN, DoS, DDoS, PortScan, BruteForce, etc.

The result: **2.8 million labeled flow records** across 8 CSV files.

We use it to train our model because:
1. It's labeled (we know which flows are attacks)
2. It uses the same statistical features we compute from live traffic
3. It's the most cited NIDS dataset in academic papers (your model
   can be compared to published results)

### How We Process It

1. **Load** — `src/data/dataset_loader.py` reads the CSV files in
   chunks (50,000 rows at a time) to avoid running out of RAM
2. **Sample** — we cap BENIGN at 100,000 rows and attacks at 20,000
   each to prevent class imbalance
3. **Clean** — `src/data/preprocessor.py` removes rows with NaN
   (missing values) or Infinity (division by zero errors from
   CICFlowMeter)
4. **Align** — `src/data/feature_alignment.py` maps CICIDS column
   names to our feature names (they use different naming conventions)
5. **Split** — 80% for training, 20% for testing (stratified so each
   class has the same ratio in both sets)
6. **Scale** — StandardScaler normalizes all features

---

## 7. What is Machine Learning?

Machine learning is teaching a computer to find patterns in data
without explicitly programming the rules.

Traditional approach:

IF syn_count > 100 AND ack_count == 0 THEN "port scan"

Problem: attackers can change their tools to evade fixed rules.

ML approach:
Show the model 10,000 examples of port scans.
Show it 100,000 examples of normal traffic.
Let it figure out the pattern itself.

The model learns that "high SYN ratio + tiny packet size + many
different destination ports + very fast IAT" = port scan, without
anyone explicitly telling it that rule.

### Supervised vs Unsupervised Learning

**Supervised** (Random Forest) — you show the model labeled examples.
"Here are 10,000 flows labeled DoS. Here are 80,000 labeled BENIGN.
Learn the difference."

**Unsupervised** (Isolation Forest) — no labels. The model only sees
BENIGN traffic and learns what "normal" looks like. Anything that
doesn't fit that pattern gets flagged as anomalous.

---

## 8. What is a Random Forest?

### Start with a Decision Tree

A decision tree asks a series of yes/no questions:

Is bytes_per_sec > 100,000?
├── YES → Is syn_count > 50?
│         ├── YES → DoS
│         └── NO  → DDoS
└── NO  → Is flow_iat_std < 0.001?
├── YES → PortScan
└── NO  → BENIGN

The tree is built by finding which feature splits the data most cleanly
at each step. This is called **Gini impurity** — a measure of how mixed
the classes are at each node.

The problem with a single tree: it tends to memorize the training data
(overfitting) and performs poorly on new data.

### The Forest

A Random Forest builds 100 decision trees, but each tree is trained on:
- A random subset of the training rows (bootstrapping)
- A random subset of the features at each split

Each tree has a slightly different view of the data and makes slightly
different mistakes. When we predict, all 100 trees vote, and the
majority wins.

This **ensemble** approach is much more robust than any single tree.
Random noise in one tree gets cancelled out by the other 99.

### In Our Code (`src/models/random_forest.py`)

```python
model = RandomForestClassifier(
    n_estimators=100,      # 100 trees
    class_weight="balanced", # compensate for unequal class sizes
    n_jobs=-1,             # use all CPU cores in parallel
)
model.fit(X_train, y_train)
```

At prediction time:
```python
# Returns the class name and confidence (probability)
label, confidence = model.predict([flow_features])
# e.g., "PortScan", 0.97  (97% confident)
```

### Feature Importance

After training, Random Forest tells us which features it relied on most.
Our top features (from training):
1. `bwd_pkt_len_mean` — backward packet length average
2. `avg_pkt_len` — overall average packet length
3. `total_fwd_bytes` — total bytes going forward
4. `bytes_per_sec` — traffic rate

These make intuitive sense: DoS attacks have extreme byte rates,
port scans have tiny packet lengths, normal web traffic has moderate
values for all of these.

---

## 9. What is an Isolation Forest?

### The Core Idea

Normal data points are densely clustered together.
Anomalies are isolated, sitting far from the clusters.

Isolation Forest exploits this by building random trees that
repeatedly split the data with random cuts. The key insight:

**Anomalies get isolated in very few cuts.**
**Normal points require many cuts to isolate.**

If you pick a random feature and a random split value, an anomaly
(sitting in empty space) gets separated immediately. A normal point
(surrounded by other normal points) takes many splits to isolate.

The **anomaly score** is the average number of splits needed to isolate
a point across all trees. Fewer splits = more anomalous.

Scores range from approximately -1 to 0:
- Score near 0 → normal (many splits needed = surrounded by normal points)
- Score near -1 → anomaly (very few splits needed = isolated)
- Our threshold: -0.5537 (learned from training data)

### Why We Train on BENIGN Only

We train the Isolation Forest exclusively on BENIGN traffic (79,938
flows). It learns the shape of normal traffic.

At inference time, when a new flow comes in:
- If it looks like BENIGN traffic → score near 0 → NORMAL
- If it's very different from BENIGN → score near -1 → ANOMALY

This catches **zero-day attacks** — attacks the Random Forest has never
seen labeled examples of. If an attacker uses a brand new technique,
the RF might call it BENIGN (it doesn't recognize it), but the IF
will flag it as ANOMALY because it doesn't look like normal traffic.

### In Our Code (`src/models/isolation_forest.py`)

```python
model = IsolationForest(
    n_estimators=100,
    contamination=0.05,  # expect 5% of training data is borderline
)
model.fit(X_benign_only)  # trained ONLY on BENIGN flows
```

---

## 10. What is StandardScaler?

Different features have wildly different scales:
- `total_bytes` might be in the millions (1,500,000 bytes)
- `syn_count` might be 1 or 2
- `duration` might be 0.05 seconds

Many ML algorithms struggle when features have such different ranges.
A feature with values in the millions will dominate a feature with
values of 0-10, even if the small-range feature is actually more useful.

StandardScaler transforms each feature so that:
- **Mean = 0** (subtract the mean)
- **Standard deviation = 1** (divide by the std)

For example, if `bytes_per_sec` has mean=5000 and std=12000:
- A flow with 5,000 bytes/sec → scaled to 0.0 (exactly average)
- A flow with 17,000 bytes/sec → scaled to 1.0 (one std above average)
- A flow with 50,000 bytes/sec → scaled to 3.75 (extreme outlier)

### Critical Rule: Fit on Train, Transform Both

We fit the scaler ONLY on training data:
```python
scaler.fit(X_train)       # learn mean and std from training data
X_train_scaled = scaler.transform(X_train)  # scale training data
X_test_scaled  = scaler.transform(X_test)   # scale test data using SAME stats
```

If we fit on test data too, we'd be "leaking" information from the
test set into the training process — the model would perform
artificially well during evaluation but fail in production.

We save the fitted scaler to disk (`models/scaler.joblib`) so that
during live detection, we scale incoming flow features using the
exact same transformation that was applied to the training data.

---

## 11. What is Flask and SocketIO?

### Flask

Flask is a Python web framework. It lets you write Python functions
that respond to HTTP requests (the same protocol used by web browsers).

```python
@app.route("/api/stats")
def get_stats():
    return jsonify({"total_packets": 1234})
```

When your browser visits `http://localhost:5001/api/stats`, Flask calls
`get_stats()` and returns the JSON response.

### The Problem with Regular HTTP for Live Data

HTTP is **request-response**. The browser asks, the server answers.
If you want live data, you'd have to ask every second:
- Browser: "Any new alerts?"
- Server: "No"
- Browser (1 second later): "Any new alerts?"
- Server: "No"
- Browser (1 second later): "Any new alerts?"
- Server: "Yes! Here's one!"

This is called **polling** — it's inefficient and creates delays.

### WebSockets and SocketIO

WebSocket is a protocol that keeps a **persistent connection** open
between browser and server. Once connected, either side can send
data to the other at any time, instantly.

**Socket.IO** builds on WebSocket and adds:
- Automatic reconnection if connection drops
- Named events (`"alert"`, `"flow"`, `"stats_update"`)
- Fallback to polling if WebSocket isn't supported

In our system:
1. Browser connects to the server via WebSocket
2. When a packet is captured → state is updated
3. Every second, the server pushes fresh stats to all connected browsers
4. When an alert fires → server instantly pushes the alert event
5. Browser JavaScript receives the event and updates the charts/feed

```python
# Server side (Python) — push to all connected browsers
socketio.emit("alert", {
    "rf_label": "PortScan",
    "confidence": 0.97,
    "flow": "TCP 192.168.1.5:54231 → 192.168.1.5:80"
})
```

```javascript
// Browser side (JavaScript) — receive and display
socket.on("alert", function(data) {
    displayAlert(data.rf_label, data.confidence, data.flow);
});
```

### The Threading Challenge

Our project has two things running simultaneously:
1. **Scapy** — capturing packets in real time (requires a dedicated thread)
2. **Flask** — serving the web dashboard (requires the main thread)

We solve this with a **queue**:
- Scapy thread puts events (alerts, flow data) into a `queue.Queue`
- A separate emit worker reads from the queue and calls `socketio.emit`
- Flask serves HTTP requests in parallel

This prevents the threads from interfering with each other.

---

## 12. How the Whole System Works Together

Here is the complete journey of a single network flow, from packet to alert:

### Step 1 — Packet Capture

You open GitHub in your browser.
Your computer sends a TCP SYN packet to `140.82.113.3:443`.

Scapy is listening on `wlo1` (your WiFi interface).
It intercepts the packet and calls our `_process_packet()` callback.

Raw packet → _process_packet() → _extract_features()

We extract: src_ip, dst_ip, src_port=54231, dst_port=443,
protocol=TCP, flags="S", packet_len=60, payload_len=0

### Step 2 — Flow Tracking

`FlowTracker.process_packet()` looks up the 5-tuple
`(192.168.1.5, 54231, 140.82.113.3, 443, TCP)` in its dictionary.

Not found → create a new Flow object.

Over the next few seconds, more packets arrive (SYN-ACK, ACK, data,
more data, FIN). Each gets added to the same Flow.

When FIN is seen → flow is complete → export.

### Step 3 — Feature Extraction

`extract_features(flow)` computes all 36 statistical features:
- duration = 3.42 seconds
- total_packets = 14
- bytes_per_sec = 8234.5
- fwd_iat_mean = 0.24 seconds
- syn_count = 1, ack_count = 12, fin_count = 1
- ... (36 features total)

### Step 4 — Preprocessing

The 36 raw feature values get passed to the `RealTimeDetector`.

First, `align_live_features()` ensures the features are in the exact
same order as when the model was trained.

Then `scaler.transform()` applies the same StandardScaler that was
fitted during training — converting raw numbers to z-scores.

### Step 5 — Random Forest Inference

The scaled 36-value vector is passed to all 100 trees simultaneously.
Each tree votes: "BENIGN", "BENIGN", "BENIGN", ..., "BENIGN".
100/100 votes for BENIGN → prediction: BENIGN, confidence: 97%

### Step 6 — Isolation Forest Inference

The same scaled vector is passed to the Isolation Forest.
It computes the average depth needed to isolate this point.
Score: -0.38 (close to 0 = easy to isolate with normal-traffic patterns)
Score > threshold (-0.55) → NORMAL

### Step 7 — Alert Decision

RF says BENIGN + IF says NORMAL → alert_level = "BENIGN" → no alert.
The flow is logged silently.

For a port scan flow, this would look different:
- RF: "PortScan" (99% confidence) → alert_level = "ATTACK" → alert!
- IF: "ANOMALY" (score = -0.68) → also flags it

### Step 8 — Dashboard Update

The `DashboardAlertEngine` puts the flow result into a `queue.Queue`.
The `emit_worker` (running in Flask's context) drains the queue every
50ms and calls `socketio.emit("flow", data)`.

The browser receives the WebSocket event instantly.
JavaScript adds a new row to the flow table, updates the chart,
increments the packet counter.

If it was an alert: a red card appears in the alert feed.

---

## 13. How to Run the Project

### First-time Setup

```bash
# 1. Clone the repository
git clone https://github.com/CRAzyAbd/nids-ml.git
cd nids-ml

# 2. Run the automated setup script
bash setup.sh
# This installs system dependencies, creates a virtual environment,
# installs Python packages, creates directories, and detects
# your network interface automatically.

# 3. Download the CICIDS-2017 dataset
# Go to: https://www.unb.ca/cic/datasets/ids-2017.html
# Download MachineLearningCSV.zip
# Extract it:
unzip ~/Downloads/MachineLearningCSV.zip -d data/raw/
```

### Preparing the Models

```bash
# Activate the virtual environment
source venv/bin/activate

# 4. Preprocess the dataset (takes ~5 minutes)
python3 main.py --mode preprocess

# 5. Train the models (takes ~10 minutes)
python3 main.py --mode train
# This creates models/random_forest.joblib and
# models/isolation_forest.joblib
```

### Running the Dashboard (Main Mode)

```bash
# Must use sudo because raw packet capture requires root privileges
sudo venv/bin/python3 main.py --mode dashboard

# Open your browser at:
# http://localhost:5001
```

### Running the Attack Demo

While the dashboard is running, open a second terminal:

```bash
cd nids-ml
source venv/bin/activate
python3 scripts/demo_attack.py
```

This simulates port scans, brute force, and DoS attacks on your
own machine so you can see the alerts fire in real time.

### Other Modes

```bash
# Terminal-only detection (no browser needed)
sudo venv/bin/python3 main.py --mode detect

# Exploratory data analysis (generates charts)
python3 main.py --mode eda

# Capture packets to CSV without detection
sudo venv/bin/python3 main.py --mode capture
```

### Command Line Options

```bash
# Change network interface
sudo venv/bin/python3 main.py --mode dashboard --interface eth0

# Change dashboard port
sudo venv/bin/python3 main.py --mode dashboard --port 8080

# Apply a BPF filter (only capture TCP traffic)
sudo venv/bin/python3 main.py --mode detect --filter "tcp"

# Capture only 500 packets then stop
sudo venv/bin/python3 main.py --mode capture --count 500
```

---

## 14. Understanding the Dashboard

Open `http://localhost:5001` while the dashboard is running.

### Stat Cards (top row)

| Card | What it Shows |
|------|--------------|
| Packets Captured | Total raw packets intercepted since startup |
| Flows Analyzed | Total completed conversations classified |
| Alerts Fired | Total non-BENIGN classifications |
| Benign Traffic | Percentage of flows classified as normal |

### Protocol Donut Chart

Shows the breakdown of captured packets by protocol:
- **TCP** — web browsing, file downloads, SSH
- **UDP** — DNS lookups, video calls, QUIC (used by Chrome)
- **ICMP** — ping, network diagnostics

### Traffic Classification Chart

Shows how flows are classified by the Random Forest.
In normal use: mostly BENIGN. During an attack: attack classes appear.

### Alert Timeline

A bar chart showing alerts per 5-second window over the last 60 seconds.
Spikes indicate bursts of suspicious activity.

### Live Alert Feed

Every non-BENIGN flow appears here with:
- 🚨 ATTACK — Random Forest confidently identified an attack class
- ⚠️ ANOMALY — RF said BENIGN but Isolation Forest disagrees
- ❓ SUSPICIOUS — RF predicted non-BENIGN but with low confidence

### Flow Table

Every completed flow (benign and malicious) in chronological order.
Green badge = BENIGN, Red = ATTACK, Purple = ANOMALY.

---

## 15. Understanding the Alerts

### Alert Types

**ATTACK** (RF confident, high confidence)

🚨 ATTACK — PortScan
Flow: TCP 192.168.1.5:54231 → 192.168.1.5:80 | 3pkts | 120B/s | 0.02s
RF: PortScan (confidence: 97.3%)

Interpretation: The Random Forest saw 97.3% agreement among its 100
trees that this flow matches port scan patterns. The flow lasted only
0.02 seconds with 3 packets — consistent with a SYN scan.

**ANOMALY** (IF flags, RF says BENIGN)

⚠️ ANOMALY — BENIGN
Flow: TCP 10.0.0.5:51234 → 192.168.1.5:9001 | 48pkts | 284B/s | 60.23s
RF: BENIGN (conf: 95.4%) — but IF flagged anomaly
IF Score: -0.572 (threshold: -0.554)

Interpretation: The RF doesn't recognize this as any known attack
type. But the Isolation Forest says this flow's statistical signature
is unusual compared to normal traffic. Could be a new attack, unusual
software, or a misconfigured application. Worth investigating.

**SUSPICIOUS** (RF says non-BENIGN but low confidence)

❓ SUSPICIOUS — DoS
RF: DoS (LOW confidence: 61.2%)

Interpretation: The RF leans toward DoS but only 61 of its 100 trees
agreed. Could be a weak attack, a borderline case, or normal traffic
that happens to share some features with DoS. Treat as a warning.

### False Positives

Our system has a 5% false alarm rate on BENIGN traffic for the
Isolation Forest. This means roughly 1 in 20 legitimate flows
gets flagged as ANOMALY.

Common legitimate traffic that triggers ANOMALY:
- Long-lived HTTPS connections (video streaming, large downloads)
- QUIC connections (Chrome's modern protocol)
- VPN tunnels (unusual byte patterns)
- High-bandwidth local network transfers

When you see an ANOMALY alert with RF confidence of 90%+ for BENIGN,
it's likely a false positive — legitimate traffic that looks unusual.

---

## 16. Common Terms Glossary

| Term | Meaning |
|------|---------|
| **BPF Filter** | Berkeley Packet Filter — a mini-language to filter packets. `"tcp"` = only TCP. `"port 80"` = only port 80. `"not port 22"` = exclude SSH. |
| **Byte** | 8 bits. The basic unit of digital data. 1 kilobyte = 1,024 bytes. |
| **Class imbalance** | When one category vastly outnumbers others in training data. We have 100k BENIGN vs 1,966 Bot — the model must handle this. |
| **Confusion matrix** | A table showing how many flows were correctly/incorrectly classified per class. The diagonal = correct. Off-diagonal = mistakes. |
| **Contamination** | Isolation Forest parameter — what fraction of training data we expect to be anomalous. We use 0.05 (5%). |
| **Daemon thread** | A background thread that automatically stops when the main program exits. We use this for the Scapy capture thread. |
| **EDA** | Exploratory Data Analysis — visualizing and summarizing a dataset before building models. |
| **F1 Score** | Harmonic mean of precision and recall. A balanced measure of classification quality. 1.0 = perfect. |
| **False negative** | An attack that was missed (classified as BENIGN). Dangerous — you didn't catch the attacker. |
| **False positive** | Normal traffic classified as an attack. Annoying — unnecessary alerts. |
| **Gini impurity** | Measure of how mixed a set of labels is. 0 = all same label (pure). Used by decision trees to choose splits. |
| **IAT** | Inter-Arrival Time — the gap between consecutive packets in a flow. |
| **joblib** | Python library for saving/loading Python objects to disk. We save our trained models with it. |
| **NaN** | Not a Number — a special floating point value indicating a missing or undefined result (e.g., 0/0). |
| **Overfitting** | When a model memorizes the training data so well it fails on new data. Prevented by Random Forest's ensembling. |
| **Precision** | Of all flows we called "DoS", what fraction were actually DoS? |
| **Recall** | Of all actual DoS flows, what fraction did we catch? |
| **Scapy** | Python library for raw packet capture and construction. |
| **SocketIO** | Library for real-time bidirectional communication between server and browser. |
| **Stratified split** | Train/test split that preserves the class ratio from the original dataset. |
| **TTL** | Time To Live — a counter in IP packets that decrements at each router. When it hits 0, the packet is discarded. Prevents infinite routing loops. |
| **Virtual environment** | An isolated Python installation for a single project. `source venv/bin/activate` switches to it. |
| **z-score** | How many standard deviations a value is from the mean. This is what StandardScaler computes. |


