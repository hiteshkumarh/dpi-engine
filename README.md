---
# 🛡️ DPI Engine – Deep Packet Inspection System

A **Deep Packet Inspection (DPI) engine** that analyzes network traffic from **PCAP files**, extracts domains from encrypted TLS connections using **SNI inspection**, and applies **rule-based filtering** to identify and block applications.

The system consists of:

* **Python DPI Engine** → performs packet parsing and traffic inspection
* **Node.js Web Dashboard** → provides a UI to upload PCAP files and visualize analysis results

This project demonstrates how encrypted traffic can still be classified by inspecting **metadata in the TLS handshake**.

---

# 📌 Problem Statement

Traditional firewalls operate mainly at:

* **Layer 3 – Network Layer (IP filtering)**
* **Layer 4 – Transport Layer (Port filtering)**

However modern applications often use **HTTPS (TLS encryption)** and share the same port.

Example:

| Application | Port |
| ----------- | ---- |
| YouTube     | 443  |
| Facebook    | 443  |
| GitHub      | 443  |
| Discord     | 443  |

If a network administrator blocks **port 443**, almost the entire internet would be blocked.

At the same time, blocking based on **IP addresses** is unreliable because large services use **CDNs and cloud infrastructure**, where IP addresses frequently change.

Therefore, it becomes difficult to **identify or control specific applications** using traditional firewall rules.

---

# 💡 Solution

This project implements a **Deep Packet Inspection engine** that inspects **metadata inside packets** rather than relying only on IP and port filtering.

The system analyzes early parts of network communication such as:

* TLS ClientHello messages
* HTTP headers
* DNS queries

The key idea is that even though HTTPS encrypts the payload, the **Server Name Indication (SNI)** inside the TLS handshake is **visible in plaintext**.

Example TLS handshake:

```
ClientHello
 └── SNI: www.youtube.com
```

Using this information the DPI engine can:

* Identify the application being accessed
* Apply rule-based filtering
* Block specific domains or apps
* Generate network traffic reports

---

# ⚙️ Features

### 📦 PCAP Packet Parsing

Reads packet captures directly from `.pcap` files using Python binary parsing.

### 🌐 Protocol Decoding

Supports parsing of:

* Ethernet
* IPv4
* TCP
* UDP

### 🔍 Deep Packet Inspection

Extracts application information using:

* TLS **Server Name Indication (SNI)**
* HTTP **Host header**
* DNS queries

### 🧠 Flow Tracking

Tracks connections using **Five-Tuple identification**

```
(Source IP, Destination IP, Source Port, Destination Port, Protocol)
```

### 🚫 Rule-Based Filtering

Traffic can be blocked using:

* IP address
* Domain name
* Application type

### 📊 Web Dashboard

Users can:

* Upload PCAP files
* Configure filtering rules
* View network traffic statistics

---

# 🏗️ System Architecture

```
User (Browser)
      │
      ▼
Node.js Web Dashboard
      │
      ▼
Python DPI Engine
      │
      ▼
Packet Parsing + Application Detection
      │
      ▼
Filtering Rules + Traffic Analysis
```

---

# 🔄 System Workflow

```
Upload PCAP
     ↓
Node.js Server
     ↓
Run Python DPI Engine
     ↓
Read PCAP packets
     ↓
Parse Ethernet / IP / TCP / UDP
     ↓
Extract TLS SNI / HTTP Host
     ↓
Classify application
     ↓
Apply filtering rules
     ↓
Generate analysis report
     ↓
Display results in dashboard
```

---

# 🌐 Network Packet Structure

Every network packet contains multiple layers:

```
Ethernet Header
   ↓
IP Header
   ↓
TCP / UDP Header
   ↓
Application Payload
```

Example structure:

```
┌─────────────────────────────┐
│ Ethernet Header (MAC)       │
├─────────────────────────────┤
│ IP Header (Source/Dest IP)  │
├─────────────────────────────┤
│ TCP Header (Ports)          │
├─────────────────────────────┤
│ Payload (TLS ClientHello)   │
└─────────────────────────────┘
```

---

# 🔍 Deep Packet Inspection Process

### 1️⃣ Read PCAP File

The engine reads raw packet bytes from a capture file.

```
Global Header
Packet Header
Packet Data
```

---

### 2️⃣ Parse Network Protocols

Each packet is decoded layer by layer to extract:

* Source IP
* Destination IP
* Ports
* Protocol

Supported protocols:

* Ethernet
* IPv4
* TCP
* UDP

---

### 3️⃣ Flow Tracking (Five-Tuple)

Packets are grouped into flows using:

```
(Source IP, Destination IP, Source Port, Destination Port, Protocol)
```

Example:

```
192.168.1.10:54321 → 142.250.185.206:443
```

All packets belonging to the same connection are tracked together.

---

### 4️⃣ TLS SNI Extraction

For HTTPS traffic, the engine inspects the **TLS ClientHello message**.

Example:

```
ClientHello
 └── SNI: www.youtube.com
```

This allows the system to identify the requested domain before encryption begins.

---

### 5️⃣ Application Classification

Extracted domains are mapped to application categories.

Example:

```
youtube.com → YouTube
facebook.com → Facebook
github.com → GitHub
```

---

### 6️⃣ Rule Engine

Filtering rules can block traffic by:

| Rule Type   | Example      |
| ----------- | ------------ |
| IP          | 192.168.1.50 |
| Application | YouTube      |
| Domain      | facebook     |

Filtering flow:

```
Packet arrives
      ↓
Check blocked IP
      ↓
Check blocked application
      ↓
Check blocked domain
      ↓
Forward or drop packet
```

---

# 📊 Example Output

```
Total Packets: 77
Forwarded: 76
Dropped: 1
Active Flows: 27
```

Application breakdown:

```
HTTPS      55
DNS        4
Twitter/X  3
HTTP       2
Google     1
YouTube    1
Facebook   1
```

Detected domains:

```
www.youtube.com
www.facebook.com
github.com
google.com
```

---

# 📂 Project Structure

```
packet_analyzer/
├── frontend/                  # Node.js Web Dashboard
│   ├── public/
│   ├── uploads/
│   ├── server.js
│   └── package.json
│
├── packet_analyzer_py/        # Python DPI Engine
│   ├── core/
│   │   ├── packet_parser.py
│   │   ├── pcap_reader.py
│   │   ├── rule_manager.py
│   │   ├── sni_extractor.py
│   │   └── types.py
│   │
│   └── main.py
│
├── test_dpi.pcap
└── generate_test_pcap.py
```

---

# 🚀 Running the Project

## 1️⃣ Clone Repository

```
git clone https://github.com/hiteshkumarh/dpi-engine.git
cd dpi-engine
```

---

## 2️⃣ Install Node Dependencies

```
cd frontend
npm install
```

---

## 3️⃣ Start Web Dashboard

```
npm start
```

or

```
node server.js
```

Open browser:

```
http://localhost:5000
```

Upload a `.pcap` file and run traffic analysis.

---

# 🖥️ Run DPI Engine via CLI

Basic analysis:

```
python packet_analyzer_py/main.py test_dpi.pcap output.pcap
```

With blocking rules:

```
python packet_analyzer_py/main.py test_dpi.pcap output.pcap \
--block-app YouTube \
--block-domain facebook \
--block-ip 192.168.1.50
```

---

# 🧪 Generate Sample Traffic

```
python generate_test_pcap.py
```

This script creates a `.pcap` file containing simulated:

* TLS traffic
* HTTP requests
* DNS queries

---

# 🧠 Technologies Used

### Backend

* Python
* Node.js
* Express.js

### Networking

* TCP/IP Protocol Analysis
* PCAP Binary Parsing
* TLS Handshake Inspection
* Deep Packet Inspection

### Frontend

* HTML
* CSS
* JavaScript

---

# 📚 Learning Outcomes

This project demonstrates:

* Network protocol parsing
* TLS handshake analysis
* Deep Packet Inspection techniques
* Flow-based network tracking
* Backend and frontend system integration

---

# 👨‍💻 Author

**Hithesh Kumar**

GitHub:
[https://github.com/hiteshkumarh](https://github.com/hiteshkumarh)

---
