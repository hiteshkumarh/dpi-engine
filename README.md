# 🛡️ DPI Engine – Deep Packet Inspection System

This project implements a **Deep Packet Inspection (DPI) engine** that analyzes network traffic from **PCAP files**, extracts domains from encrypted TLS connections using **SNI inspection**, and applies **rule-based filtering** to identify and block applications.

The system consists of:

* **Python DPI Engine** – performs packet parsing and traffic inspection
* **Node.js Web Dashboard** – provides a UI to upload PCAP files and visualize analysis results

The project includes **architecture diagrams and packet flow diagrams** to explain how packets move through the DPI pipeline and how TLS metadata is extracted.

These diagrams help understand:

* Network packet structure
* Packet processing pipeline
* DPI architecture
* TLS handshake and SNI extraction

---

# 📑 Table of Contents

1. What is DPI?
2. Networking Background
3. Project Overview
4. File Structure
5. The Journey of a Packet (Simple Version)
6. The Journey of a Packet (Multi-threaded Version)
7. Deep Dive: Each Component
8. How SNI Extraction Works
9. How Blocking Works
10. System Architecture Diagram
11. Packet Flow Diagram
12. Building and Running
13. Understanding the Output

---

# 1️⃣ What is DPI?

**Deep Packet Inspection (DPI)** is a technology used to analyze the **contents of network packets** as they pass through a monitoring system.

Unlike traditional firewalls that only inspect **IP addresses and ports**, DPI examines **packet payload data** to determine the actual application being used.

### Real-World Uses

| Use Case          | Example                                |
| ----------------- | -------------------------------------- |
| ISPs              | Throttle or block BitTorrent traffic   |
| Enterprises       | Block social media during office hours |
| Parental Controls | Filter inappropriate websites          |
| Security Systems  | Detect malware or suspicious traffic   |

### What Our DPI Engine Does

```
User Traffic (PCAP) → [DPI Engine] → Filtered Traffic (PCAP)
                           ↓
                    - Identifies apps (YouTube, Facebook, etc.)
                    - Blocks based on rules
                    - Generates reports
```

---

# 2️⃣ Networking Background

To understand DPI, it's important to understand how **network packets are structured**.

The following diagram illustrates the **network protocol stack** used when data travels across the internet.

```
┌─────────────────────────────────────────────┐
│ Layer 7: Application   │ HTTP, TLS, DNS     │
├─────────────────────────────────────────────┤
│ Layer 4: Transport     │ TCP, UDP           │
├─────────────────────────────────────────────┤
│ Layer 3: Network       │ IP                 │
├─────────────────────────────────────────────┤
│ Layer 2: Data Link     │ Ethernet           │
└─────────────────────────────────────────────┘
```

---

# Packet Structure Diagram

Each network packet contains **multiple nested protocol headers**.

```
┌──────────────────────────────────────────────┐
│ Ethernet Header                              │
│ ┌──────────────────────────────────────────┐ │
│ │ IP Header                                │ │
│ │ ┌──────────────────────────────────────┐ │ │
│ │ │ TCP Header                           │ │ │
│ │ │ ┌──────────────────────────────────┐ │ │ │
│ │ │ │ Application Payload              │ │ │ │
│ │ │ │ (TLS ClientHello / HTTP Data)    │ │ │ │
│ │ │ └──────────────────────────────────┘ │ │ │
│ │ └──────────────────────────────────────┘ │ │
│ └──────────────────────────────────────────┘ │
└──────────────────────────────────────────────┘
```

---

# 3️⃣ Project Overview

The DPI system processes captured network packets and extracts application information.

```
PCAP Capture
      │
      ▼
Node.js Web Dashboard
(upload + API layer)
      │
      ▼
Python DPI Engine
(packet parsing + inspection)
      │
      ▼
Traffic Classification
(SNI extraction + rules)
      │
      ▼
Traffic Report + Dashboard Visualization
```

---

# 4️⃣ File Structure

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
├── generate_test_pcap.py
└── README.md
```

---

# The Journey of a Packet (Simple Version)

In the **single-threaded version**, packets are processed sequentially.

```
PCAP Reader
     │
     ▼
Packet Parser
     │
     ▼
Flow Tracking (Five-Tuple)
     │
     ▼
SNI / HTTP Host Extraction
     │
     ▼
Application Classification
     │
     ▼
Rule Engine
     │
     ▼
Forward Packet or Drop Packet
```

### Step 1 – Read Packet From PCAP

```
Global Header
Packet Header
Packet Data
```

Each packet contains:

* timestamp
* captured length
* raw packet bytes

---

### Step 2 – Parse Protocol Headers

```
Ethernet → IP → TCP / UDP → Payload
```

Extracted fields:

* Source IP
* Destination IP
* Source Port
* Destination Port
* Protocol

---

### Step 3 – Create Flow Identifier

```
(Source IP, Destination IP, Source Port, Destination Port, Protocol)
```

Example flow:

```
192.168.1.10:54321 → 142.250.185.206:443
```

---

### Step 4 – Extract Domain Information

```
TLS SNI      → www.youtube.com
HTTP Host    → github.com
DNS Query    → google.com
```

---

### Step 5 – Classify Application

```
youtube.com  → YouTube
facebook.com → Facebook
github.com   → GitHub
```

---

### Step 6 – Apply Filtering Rules

Traffic can be blocked using:

* IP address
* application type
* domain name

```
Allowed → forward packet
Blocked → drop packet
```

---

# The Journey of a Packet (Multi-threaded Version)

```
Reader Thread
      │
      ▼
Load Balancer Threads
      │
      ▼
Fast Path Worker Threads
      │
      ▼
Output Queue
      │
      ▼
Output Writer
```

| Thread            | Responsibility           |
| ----------------- | ------------------------ |
| Reader            | Reads packets from PCAP  |
| Load Balancer     | Distributes packets      |
| Fast Path Workers | Perform DPI processing   |
| Output Writer     | Writes processed packets |

---

# Deep Dive: Each Component

### PCAP Reader

Responsible for:

* opening PCAP files
* validating headers
* reading packet data

---

### Packet Parser

Parses protocol layers:

* Ethernet
* IPv4
* TCP
* UDP

---

### SNI Extractor

Extracts domain names from TLS ClientHello messages.

---

### Rule Manager

Applies filtering rules based on:

* IP
* domain
* application

---

### Flow Tracker

Tracks connections using the **five-tuple identifier**.

---

# How SNI Extraction Works

```
ClientHello
   └── Extensions
        └── SNI
             └── www.youtube.com
```

### TLS Handshake

```
Client (Browser)                 Server
      │                             │
      │ ---- ClientHello ----------►│
      │      SNI: youtube.com       │
      │                             │
      │ ◄---- ServerHello ----------│
      │                             │
      │ ==== Encrypted Traffic ==== │
```

---

# How Blocking Works

| Rule Type   | Example      |
| ----------- | ------------ |
| IP          | 192.168.1.50 |
| Application | YouTube      |
| Domain      | facebook     |

```
Packet arrives
      │
      ▼
Check blocked IP
      │
      ▼
Check blocked application
      │
      ▼
Check blocked domain
      │
      ▼
Forward or Drop
```

---

# System Architecture Diagram

```
User Browser
      │
      ▼
Node.js Web Dashboard
      │
      ▼
Python DPI Engine
      │
      ▼
Packet Parsing
      │
      ▼
Traffic Classification
      │
      ▼
Filtering + Analysis
```

---

# Packet Flow Diagram

```
PCAP File
   │
   ▼
Packet Reader
   │
   ▼
Protocol Parser
   │
   ▼
Flow Tracker
   │
   ▼
SNI Extractor
   │
   ▼
Rule Engine
   │
   ▼
Output / Report
```

---

# Building and Running

### Clone Repository

```bash
git clone https://github.com/hiteshkumarh/dpi-engine.git
cd dpi-engine
```

### Install Dependencies

```bash
cd frontend
npm install
```

### Start Dashboard

```bash
npm start
```

or

```bash
node server.js
```

Open:

```
http://localhost:5000
```

---

# Understanding the Output

Example report:

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

The report provides insights into:

* traffic distribution
* application usage
* blocked connections
* network behavior

---
