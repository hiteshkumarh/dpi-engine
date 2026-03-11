# DPI Engine - Deep Packet Inspection Analyzer

A powerful Deep Packet Inspection (DPI) system designed to identify and filter network traffic by parsing the internal payloads of network packets. This engine can intercept TLS Client Hellos to extract Server Name Indications (SNI) and HTTP Host headers without decryption, enabling you to identify and block specific applications (like YouTube, TikTok, Facebook) regardless of encryption.

This project is fully powered by **Python 3** for core networking logic and **Node.js/Express** for a clean, accessible Web Dashboard.

---

## 🚀 Features

- **Raw PCAP Parsing**: Decodes Ethernet, IPv4, TCP, and UDP completely from scratch in Python.
- **Deep Packet Inspection**:
  - Extracts SNI from TLS 1.0-1.3 Client Hello messages natively.
  - Extracts `Host` headers from standard HTTP traffic.
  - Parses standard DNS requests.
- **Flow Tracking stateful analysis**: Associates multiple packets with a single unified conversation stream (Five-Tuple tracking).
- **Rule-Based Filtering**: Block outgoing access dynamically by Application Name, Domain, or Source IP.
- **Web Interface**: A sleek web UI to upload captures, configure rules, and generate real-time processing reports.

---

## 📦 Project Structure

```text
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

## 🛠️ Installation & Setup

You will need **Python 3.10+** and **Node.js (LTS)** installed on your machine. Using Windows, macOS, or Linux is fully supported.

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/packet_analyzer.git
cd packet_analyzer
```

*(Note: The Python engine uses only standard libraries, so there is no `requirements.txt` needed!)*

### 2. Install UI Dependencies

Navigate into the frontend directory and install the required Node packages:

```bash
cd frontend
npm install
```

---

## 🖥️ Running the Application

### Option 1: Web Dashboard (Recommended)

1. Start the Node.js API and Web Server:
   ```bash
   cd frontend
   npm start
   ```
2. Open your browser to `http://localhost:5000`
3. Upload a PCAP file (e.g., `test_dpi.pcap` from the root folder).
4. Select applications to block or pass and view your DPI filtering results instantly.

### Option 2: Command Line Interface (CLI)

You can run the DPI engine manually from the terminal for faster scripting flows:

```bash
# Basic Run
python packet_analyzer_py/main.py test_dpi.pcap output.pcap

# With Blocking Rules
python packet_analyzer_py/main.py test_dpi.pcap output.pcap \
    --block-app YouTube \
    --block-app TikTok \
    --block-ip 192.168.1.50 \
    --block-domain facebook
```

---

## 🧪 Generating Test Data

If you need a mock `.pcap` capture file to experiment on, use the included Python script:

```bash
python generate_test_pcap.py
```
This generates a realistic network flow containing simulated TLS, HTTP, and DNS traffic routed to standard applications. 
