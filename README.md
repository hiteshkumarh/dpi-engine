# 🛡️ DPI Engine – Deep Packet Inspection Analyzer

A **Deep Packet Inspection (DPI) system** that analyzes network traffic from PCAP files, extracts domains from encrypted TLS connections using **SNI inspection**, and applies **rule-based filtering** to identify and block applications.

The project combines a **Python packet analysis engine** with a **Node.js web dashboard** for visualizing network traffic statistics.

---

## 📌 Problem Statement

Traditional firewalls mainly operate at **Layer 3 and Layer 4 of the network stack**, filtering traffic based on **IP addresses and port numbers**.

This approach worked well in the past, but modern applications use **HTTPS (TLS encryption)** where many different services share the same port.

Example:

| Application | Port |
| ----------- | ---- |
| YouTube     | 443  |
| Facebook    | 443  |
| GitHub      | 443  |
| Discord     | 443  |

If a network administrator blocks **port 443**, it would block almost the entire internet.

At the same time, blocking based on **IP addresses** is unreliable because large services use **CDNs and cloud infrastructure**, where IP addresses change frequently.

As a result, administrators cannot easily block or analyze specific applications when traffic is encrypted.

---

## 💡 Solution

This project implements a **Deep Packet Inspection (DPI) Engine** that analyzes network traffic beyond basic IP and port filtering.

Instead of decrypting traffic, the engine inspects **metadata present in the early stages of a connection**.

Key techniques used:

* **TLS Client Hello Inspection**
  Extracts the **Server Name Indication (SNI)** field from TLS handshakes, revealing the requested domain (e.g., `youtube.com`) before encryption is fully established.

* **HTTP Header Parsing**
  Extracts the `Host` header from unencrypted HTTP traffic.

* **DNS Query Parsing**
  Identifies requested domains from DNS requests.

Using this information, the system can:

* Identify applications such as **YouTube, Facebook, GitHub, or Discord**
* Apply **rule-based filtering**
* Block or allow traffic dynamically
* Generate traffic analysis reports

The engine is implemented in **Python**, while a **Node.js web dashboard** allows users to upload PCAP files, configure rules, and visualize results easily.

---

# ⚙️ Features

* 📦 **Raw PCAP Parsing**

  * Reads packet captures directly using Python.

* 🌐 **Protocol Decoding**

  * Ethernet
  * IPv4
  * TCP
  * UDP

* 🔍 **Deep Packet Inspection**

  * Extract TLS **SNI (Server Name Indication)**
  * Extract HTTP **Host headers**
  * Parse DNS queries

* 🧠 **Flow Tracking**

  * Tracks connections using **5-tuple flow identification**

* 🚫 **Rule-Based Filtering**

  * Block by:

    * Domain
    * Application
    * IP address

* 📊 **Web Dashboard**

  * Upload PCAP files
  * Configure filtering rules
  * View analysis results

---

# 🏗️ System Architecture

```text
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
```

# project Workflow:

```
Upload PCAP
     ↓
Node.js Server
     ↓
Run Python DPI Engine
     ↓
Parse Ethernet/IP/TCP/UDP
     ↓
Extract TLS SNI / HTTP Host
     ↓
Apply Filtering Rules
     ↓
Generate Analysis Report
     ↓
Display Results in Web Dashboard
```

---

# 📂 Project Structure

```
packet_analyzer/
├── frontend/                  # Web Interface (Express.js)
│   ├── public/                # Static UI assets (HTML, CSS, JS)
│   ├── uploads/               # PCAP uploads directory
│   ├── server.js              # Node.js backend
│   └── package.json           # Node dependencies
│
├── packet_analyzer_py/        # Python DPI Engine
│   ├── core/                  # Core parsing modules
│   │   ├── packet_parser.py   # Ethernet/IP/TCP/UDP parsing
│   │   ├── pcap_reader.py     # Binary PCAP format reading
│   │   ├── rule_manager.py    # IP/Domain blocking logic
│   │   ├── sni_extractor.py   # TLS SNI & HTTP Host parsing
│   │   └── types.py           # Enums, 5-Tuple definition
│   │
│   └── main.py                # Python CLI Entry Point
│
├── test_dpi.pcap              # Sample network traffic file
└── generate_test_pcap.py      # Script to generate sample PCAP
```

---

## 🚀 Clone and Run the Project Locally

Follow these steps to run the DPI Engine on your machine.

### 1️⃣ Clone the Repository

```bash
git clone https://github.com/hiteshkumarh/dpi-engine.git
```

### 2️⃣ Navigate to the Project Folder

```bash
cd dpi-engine
```

You should see the following structure:

```
frontend/
packet_analyzer_py/
test_dpi.pcap
generate_test_pcap.py
```

---

## 🛠️ Install Dependencies

This project uses **Node.js for the dashboard** and **Python for the DPI engine**.

### Install Node.js dependencies

```bash
cd frontend
npm install
```

---

## ▶️ Run the Web Dashboard (Recommended)

Start the backend server:

```bash
npm start
```

or

```bash
node server.js
```

Then open your browser:

```
http://localhost:5000
```

Upload a `.pcap` file (example: `test_dpi.pcap`) and apply filtering rules.

---

## 🖥️ Run the DPI Engine from CLI

You can also run the engine directly without the web dashboard.

Return to the root folder:

```bash
cd ..
```

### Basic analysis

```bash
python packet_analyzer_py/main.py test_dpi.pcap output.pcap
```

### Run with blocking rules

```bash
python packet_analyzer_py/main.py test_dpi.pcap output.pcap --block-app YouTube --block-domain facebook
```

This will analyze the PCAP file and generate a filtered output file.

---

## 🧪 Generate Test PCAP

If you want to generate sample traffic:

```bash
python generate_test_pcap.py
```

This will create a test `.pcap` file with simulated traffic.

---

# 🛠️ Requirements

Install the following:

* **Python 3.10+**
* **Node.js (LTS)**
* **npm**

Check installations:

```
python --version
node --version
npm --version
```

---

# ⚡ Running the Project Locally

## 1️⃣ Install Node.js Dependencies

```
cd frontend
npm install
```

---

## 2️⃣ Start the Web Server

```
npm start
```

or

```
node server.js
```

---

## 3️⃣ Open the Web Dashboard

Open your browser and go to:

```
http://localhost:5000
```

---

## 4️⃣ Upload a PCAP File

Upload the included test capture:

```
test_dpi.pcap
```

Then add filtering rules such as:

```
youtube
```

The dashboard will analyze traffic and display statistics.

---

# 🖥️ Running the Engine via CLI

You can run the DPI engine directly using Python.

### Basic Analysis

```
python packet_analyzer_py/main.py test_dpi.pcap output.pcap
```

### With Blocking Rules

```
python packet_analyzer_py/main.py test_dpi.pcap output.pcap \
    --block-app YouTube \
    --block-domain facebook \
    --block-ip 192.168.1.50
```

---

# 🧪 Generate Test PCAP Traffic

If you want to create sample network traffic:

```
python generate_test_pcap.py
```

This script generates a `.pcap` file with simulated TLS, HTTP, and DNS flows.

---

# 📊 Example Output

```
Total Packets: 77
Forwarded: 76
Dropped: 1
Active Flows: 27
```

Application Breakdown:

```
HTTPS      55
DNS        4
Twitter/X  3
HTTP       2
Google     1
YouTube    1
Facebook   1
```

---

# 🧠 Technologies Used

**Backend**

* Python 3
* Node.js
* Express.js

**Networking**

* PCAP Binary Parsing
* TCP/IP Protocol Analysis
* TLS Handshake Inspection

**Frontend**

* HTML
* CSS
* JavaScript

---

# 📚 Learning Outcomes

This project demonstrates:

* Deep Packet Inspection techniques
* Network protocol parsing
* TLS handshake analysis
* Flow-based traffic tracking
* Backend and frontend integration

---

# 👨‍💻 Author

**Hithesh Kumar**




