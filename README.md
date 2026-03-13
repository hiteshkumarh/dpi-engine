

## 1. What is DPI?

Deep Packet Inspection (DPI) is a network analysis technique used to inspect the **contents of network packets** as they pass through a monitoring point in a network.

Unlike traditional firewalls that only analyze **packet headers** (such as source IP, destination IP, and port numbers), DPI examines the **packet payload** to identify the actual application or service generating the traffic.

By analyzing deeper protocol information, DPI systems can detect, classify, and control network traffic with much higher accuracy.

---

### Real-World Uses

Deep Packet Inspection is widely used in modern networking systems:

* **Internet Service Providers (ISPs)** – Identify or throttle bandwidth-heavy applications such as BitTorrent or streaming services
* **Enterprise Networks** – Restrict access to social media or non-work applications
* **Parental Control Systems** – Block access to inappropriate websites
* **Cybersecurity Systems** – Detect malicious traffic, malware communication, or intrusion attempts

---

### What This Project Demonstrates

This project implements a **Python-based Deep Packet Inspection engine** that processes **PCAP network capture files**, analyzes packet contents, and applies filtering rules.

The DPI engine performs the following tasks:

* Parses network packets from PCAP files
* Extracts domain names from **TLS handshakes using SNI inspection**
* Classifies traffic into applications (YouTube, Facebook, etc.)
* Applies rule-based filtering (IP, domain, or application blocking)
* Generates traffic analysis statistics

---

### High-Level Workflow

```
PCAP Network Capture
        │
        ▼
   DPI Engine (Python)
        │
        ├── Packet Parsing
        ├── SNI Extraction
        ├── Traffic Classification
        └── Rule Filtering
        │
        ▼
Filtered PCAP Output + Traffic Report
```


## 2. Networking Background

To understand how a Deep Packet Inspection engine works, it is important to understand how network communication is structured.

### The Network Stack (Layers)

When a user accesses a website, the data travels through multiple layers of the networking stack. Each layer adds its own header containing information required for communication.

```
┌─────────────────────────────────────────────────────────┐
│ Layer 7: Application    │ HTTP, TLS, DNS                │
├─────────────────────────────────────────────────────────┤
│ Layer 4: Transport      │ TCP (reliable), UDP (fast)    │
├─────────────────────────────────────────────────────────┤
│ Layer 3: Network        │ IP addresses (routing)        │
├─────────────────────────────────────────────────────────┤
│ Layer 2: Data Link      │ MAC addresses (local network) │
└─────────────────────────────────────────────────────────┘
```

Each layer wraps the data with additional metadata before transmitting it across the network.

---

### Packet Structure

A network packet is composed of multiple nested headers. Each protocol layer adds its own header around the payload.

```
┌──────────────────────────────────────────────────────────────────┐
│ Ethernet Header (14 bytes)                                       │
│ ┌──────────────────────────────────────────────────────────────┐ │
│ │ IP Header (20 bytes)                                         │ │
│ │ ┌──────────────────────────────────────────────────────────┐ │ │
│ │ │ TCP Header (20 bytes)                                    │ │ │
│ │ │ ┌──────────────────────────────────────────────────────┐ │ │ │
│ │ │ │ Payload (Application Data)                           │ │ │ │
│ │ │ │ Example: TLS Client Hello containing SNI             │ │ │ │
│ │ │ └──────────────────────────────────────────────────────┘ │ │ │
│ │ └──────────────────────────────────────────────────────────┘ │ │
│ └──────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

The DPI engine parses these headers sequentially to extract important information such as:

* Source IP
* Destination IP
* Source Port
* Destination Port
* Protocol type

---

### The Five-Tuple (Flow Identification)

A network connection (also called a **flow**) is uniquely identified using five parameters.

| Field            | Example        | Purpose                    |
| ---------------- | -------------- | -------------------------- |
| Source IP        | 192.168.1.100  | Device sending the traffic |
| Destination IP   | 172.217.14.206 | Destination server         |
| Source Port      | 54321          | Client application port    |
| Destination Port | 443            | Service being accessed     |
| Protocol         | TCP (6)        | Transport protocol         |

This combination is known as the **Five-Tuple**.

**Why is this important?**

* All packets with the same five-tuple belong to the same connection.
* DPI systems use this to track **flows instead of individual packets**.
* If a connection is blocked, **all packets belonging to that flow are blocked**.

---

### What is SNI?

**Server Name Indication (SNI)** is an extension of the TLS protocol used during the HTTPS handshake.

When a user visits a secure website such as:

```
https://www.youtube.com
```

the browser sends a **TLS Client Hello** message to the server.

This message contains the domain name in plaintext before encryption begins.

Example TLS Client Hello structure:

```
TLS Client Hello
├── Version: TLS 1.2
├── Random: [32 bytes]
├── Cipher Suites: [list]
└── Extensions
    └── SNI Extension
        └── Server Name: "www.youtube.com"
```

Although HTTPS encrypts most of the communication, the **SNI field remains visible in the initial handshake**.

This allows DPI systems to identify the destination domain even when the traffic is encrypted.

The DPI engine in this project extracts the **SNI field** to classify traffic and apply filtering rules.

## 3. Project Overview

### What This Project Does

This project implements a **Deep Packet Inspection (DPI) system** that analyzes network traffic captured in **PCAP files**, identifies applications using **TLS SNI inspection**, and applies rule-based filtering.

The system reads captured packets, inspects protocol headers and payload metadata, classifies traffic by application, and optionally blocks traffic based on configured rules.

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│ Wireshark   │     │  DPI Engine  │     │   Output    │
│ Capture     │ ──► │   (Python)   │ ──► │ Filtered    │
│ input.pcap  │     │              │     │ PCAP +      │
└─────────────┘     │ - Parse      │     │ Report      │
                    │ - Classify   │     └─────────────┘
                    │ - Block      │
                    │ - Analyze    │
                    └──────────────┘
```

The DPI engine performs the following tasks:

* Parses packet headers (Ethernet, IP, TCP/UDP)
* Tracks network flows using the **Five-Tuple**
* Extracts domain names from **TLS Client Hello (SNI)**
* Classifies applications based on domain patterns
* Applies rule-based filtering
* Generates traffic statistics and reports

---

### System Components

The project contains two main components:

**1. Python DPI Engine**

Responsible for the core packet processing:

* Reading packets from PCAP files
* Parsing network protocol headers
* Extracting domain names from TLS SNI
* Tracking connections using the five-tuple
* Applying blocking rules
* Writing filtered packets to a new PCAP file

**2. Node.js Web Dashboard**

Provides a user-friendly interface to:

* Upload PCAP files
* Run DPI analysis
* View traffic statistics
* Inspect detected domains and applications

---

### Processing Pipeline

```
PCAP Capture
     │
     ▼
Python DPI Engine
     │
     ├── Packet Parser
     ├── Flow Tracker
     ├── SNI Extractor
     └── Rule Manager
     │
     ▼
Filtered PCAP Output
     │
     ▼
Web Dashboard Visualization
```

---

### Processing Mode

The current implementation processes packets using a **single-threaded pipeline**.

| Mode            | File                         | Use Case                                         |
| --------------- | ---------------------------- | ------------------------------------------------ |
| Single-threaded | `packet_analyzer_py/main.py` | Learning, debugging, and analyzing PCAP captures |

This design keeps the packet inspection pipeline simple and easy to understand while demonstrating the core concepts behind Deep Packet Inspection systems.


## 4. File Structure

The repository is organized into two main components: the **Python DPI engine** and the **Node.js web dashboard**.

```
Packet_analyzer-main/

├── README.md                     # Main project documentation
├── project_documentation.md      # Detailed technical documentation
├── generate_test_pcap.py         # Script to generate test PCAP files
├── test_dpi.pcap                 # Sample PCAP file for testing
│
├── frontend/                     # Node.js Web Dashboard
│   ├── package.json              # Node.js dependencies
│   ├── server.js                 # Backend server for handling API requests
│   ├── test_api.js               # Script to test backend endpoints
│   │
│   ├── public/                   # Frontend user interface
│   │   ├── index.html            # Dashboard UI
│   │   ├── style.css             # UI styling
│   │   └── app.js                # Frontend logic
│   │
│   └── uploads/                  # Uploaded PCAP files and generated outputs
│
└── packet_analyzer_py/           # Python Deep Packet Inspection Engine
    ├── main.py                   # Main analyzer entry point
    │
    └── core/                     # Core packet inspection modules
        ├── pcap_reader.py        # Reads packets from PCAP files
        ├── packet_parser.py      # Parses Ethernet/IP/TCP/UDP headers
        ├── sni_extractor.py      # Extracts TLS Server Name Indication (SNI)
        ├── rule_manager.py       # Blocking rule management
        └── types.py              # Shared data structures
```

---

### Core Components

**Python DPI Engine (`packet_analyzer_py/`)**

Responsible for the packet inspection pipeline:

* Reading packets from PCAP files
* Parsing network protocol headers
* Extracting domain names from TLS SNI
* Classifying applications
* Applying blocking rules
* Writing filtered packets to output PCAP files

---

**Node.js Dashboard (`frontend/`)**

Provides a web interface that allows users to:

* Upload PCAP files
* Run DPI analysis
* View traffic statistics
* Inspect detected applications and domains

---

### Supporting Files

| File                       | Purpose                                  |
| -------------------------- | ---------------------------------------- |
| `generate_test_pcap.py`    | Generates sample traffic captures        |
| `test_dpi.pcap`            | Example PCAP file for testing            |
| `project_documentation.md` | Detailed explanation of DPI architecture |

---
---

## 5. The Journey of a Packet (Simple Version)

This section traces how a **single network packet flows through the Python DPI engine**.

The main processing pipeline is implemented in:

```
packet_analyzer_py/main.py
```

The packet passes through several stages: reading, parsing, inspection, classification, rule evaluation, and output generation.

---

# Step 1: Read the PCAP File

The DPI engine first opens the PCAP file and reads its global header.

📂 **File:**
`packet_analyzer_py/core/pcap_reader.py`

Example:

```python
from core.pcap_reader import PcapReader

reader = PcapReader()
reader.open("capture.pcap")
```

### What happens

* The file is opened in **binary mode**
* The **24-byte PCAP global header** is read
* The engine verifies the **PCAP magic number**
* The file is prepared for packet-by-packet reading

### PCAP File Format

```
┌────────────────────────────┐
│ Global Header (24 bytes)   │
├────────────────────────────┤
│ Packet Header (16 bytes)   │
│ Packet Data (variable)     │
├────────────────────────────┤
│ Packet Header (16 bytes)   │
│ Packet Data (variable)     │
└────────────────────────────┘
```

Relevant implementation:

```python
def read_next_packet(self) -> RawPacket | None:
    header_bytes = self.file.read(16)
    if len(header_bytes) < 16:
        return None

    unpacked = struct.unpack(self._packet_fmt, header_bytes)

    packet_header = PcapPacketHeader(
        ts_sec=unpacked[0],
        ts_usec=unpacked[1],
        incl_len=unpacked[2],
        orig_len=unpacked[3]
    )

    data = self.file.read(packet_header.incl_len)
    return RawPacket(header=packet_header, data=data)
```

---

# Step 2: Read Each Packet

The engine continuously reads packets from the PCAP file.

📂 **File:**
`packet_analyzer_py/main.py`

Example:

```python
while True:
    raw = reader.read_next_packet()
    if raw is None:
        break
```

### What happens

* The **16-byte packet header** is read
* The packet payload is extracted
* Processing continues until the **end of file**

---

# Step 3: Parse Protocol Headers

The packet is parsed to extract network protocol information.

📂 **File:**
`packet_analyzer_py/core/packet_parser.py`

Example:

```python
parsed = PacketParser.parse(raw)
```

### Packet Layout

```
raw.data bytes:

[0-13]   Ethernet Header
[14-33]  IP Header
[34-53]  TCP Header
[54+]    Payload
```

Example parsing code:

```python
parsed.src_port = struct.unpack(">H", data[offset : offset+2])[0]
parsed.dest_port = struct.unpack(">H", data[offset+2 : offset+4])[0]

parsed.seq_number = struct.unpack(">I", data[offset+4 : offset+8])[0]
parsed.ack_number = struct.unpack(">I", data[offset+8 : offset+12])[0]
```

After parsing:

```
src_ip    = 192.168.1.100
dest_ip   = 172.217.14.206
src_port  = 54321
dest_port = 443
protocol  = TCP
```

---

# Step 4: Create the Five-Tuple (Flow Tracking)

Packets are grouped into connections using a **five-tuple identifier**.

📂 **File:**
`packet_analyzer_py/main.py`

Example:

```python
tuple_key = FiveTuple(
    src_ip=parsed.src_ip_int,
    dst_ip=parsed.dest_ip_int,
    src_port=parsed.src_port,
    dst_port=parsed.dest_port,
    protocol=parsed.protocol
)
```

### What happens

A **dictionary of flows** is used to track connections:

```
flows = {
    FiveTuple → Flow
}
```

If a flow already exists:

```
Use existing flow
```

Otherwise:

```
Create new flow entry
```

This ensures packets belonging to the same connection are tracked together.

---

# Step 5: Extract SNI (Deep Packet Inspection)

For HTTPS traffic (**port 443**), the engine inspects the TLS handshake.

📂 **File:**
`packet_analyzer_py/core/sni_extractor.py`

Example:

```python
sni = SNIExtractor.extract(payload_data)
```

Relevant code:

```python
if extension_type == SNIExtractor.EXTENSION_SNI:

    sni_type = payload[offset + 2]
    sni_length = SNIExtractor.read_uint16_be(payload, offset + 3)

    if sni_type == SNIExtractor.SNI_TYPE_HOSTNAME:
        return payload[offset + 5 : offset + 5 + sni_length].decode("utf-8")
```

Example extracted domain:

```
www.youtube.com
```

### TLS Client Hello Structure

```
TLS Client Hello
├── Version
├── Random
├── Cipher Suites
└── Extensions
    └── SNI Extension
        └── Server Name: www.youtube.com
```

The DPI engine uses this domain to **identify the application**.

---

# Step 6: Check Blocking Rules

Blocking rules are evaluated for each flow.

📂 **File:**
`packet_analyzer_py/core/rule_manager.py`

Example:

```python
block_reason = rules.should_block(
    src_ip=tuple_key.src_ip,
    dst_port=tuple_key.dst_port,
    app=flow.app_type,
    domain=flow.sni
)
```

Relevant rule evaluation code:

```python
if self.is_ip_blocked(src_ip):
    return BlockReason(BlockReasonType.IP, self.ip_to_string(src_ip))

if self.is_app_blocked(app):
    return BlockReason(BlockReasonType.APP, app_type_to_string(app))

if domain and self.is_domain_blocked(domain):
    return BlockReason(BlockReasonType.DOMAIN, domain)
```

Rule types supported:

```
IP Blocking
Application Blocking
Domain Blocking
Port Blocking
```

---

# Step 7: Forward or Drop the Packet

Depending on rule evaluation:

📂 **File:**
`packet_analyzer_py/main.py`

```python
if flow.blocked:
    dropped += 1
else:
    forwarded += 1
    out_f.write(hdr_bytes)
    out_f.write(raw.data)
```

* Blocked packets are **dropped**
* Allowed packets are written to the **output PCAP file**

---

# Step 8: Generate the Final Report

After processing all packets, statistics are printed.

📂 **File:**
`packet_analyzer_py/main.py`

Example output:

```
Total Packets: 77
Forwarded: 70
Dropped: 7
Active Flows: 27
```

### Application Breakdown

```
HTTPS       55
DNS          4
Twitter/X    3
HTTP         2
YouTube      1
Facebook     1
Instagram    1
...
```

The engine also prints detected domains:

```
[Detected Applications/Domains]
  - www.youtube.com -> YouTube
  - github.com -> GitHub
  - discord.com -> Discord
```



## 6. Scalable Architecture (Future Multi-Threaded Design)

The current Python implementation processes packets in a **single-threaded pipeline**.
However, production Deep Packet Inspection systems often use **multi-threaded architectures** to process millions of packets per second.

A scalable design could distribute packet processing across multiple worker threads.

### Architecture Overview

```
                    ┌─────────────────┐
                    │  Reader Thread  │
                    │  (reads PCAP)   │
                    └────────┬────────┘
                             │
              ┌──────────────┴──────────────┐
              │      hash(5-tuple)          │
              ▼                             ▼
      ┌──────────────┐              ┌──────────────┐
      │ Worker 1     │              │ Worker 2     │
      │ DPI Engine   │              │ DPI Engine   │
      └──────┬───────┘              └──────┬───────┘
             │                             │
             └──────────────┬──────────────┘
                            ▼
                  ┌───────────────────┐
                  │ Output Queue      │
                  └─────────┬─────────┘
                            ▼
                  ┌───────────────────┐
                  │ Output Writer     │
                  └───────────────────┘
```

---

### Why This Architecture?

A multi-threaded DPI pipeline improves performance by distributing work across multiple CPU cores.

Key design ideas:

**Reader Thread**

* Reads packets from the PCAP file
* Converts raw packets into internal structures
* Distributes packets to worker threads

**Worker Threads**

Each worker performs:

* Packet parsing
* Flow tracking
* SNI extraction
* Rule evaluation

**Output Writer**

* Collects processed packets
* Writes allowed packets to the output PCAP

---

### Consistent Hashing

To maintain correct flow tracking, packets belonging to the same connection must always be processed by the same worker thread.

Example connection:

```
192.168.1.100:54321 → 142.250.185.206:443
```

All packets of this flow must be processed by the **same worker**.

```
Packet 1 (SYN)         → Worker 2
Packet 2 (SYN-ACK)     → Worker 2
Packet 3 (ClientHello) → Worker 2
Packet 4 (Data)        → Worker 2
```

This ensures the worker maintains **correct flow state**.

---

### Possible Python Implementation

A future version could use:

* `threading`
* `multiprocessing`
* `asyncio`
* queue-based worker pools

Example worker pipeline:

```
Reader → Queue → Worker Threads → Output Queue → Writer
```

# 7. Deep Dive: Each Component

This section explains the main modules that make up the **Python DPI engine** and how they work internally.

---

# PCAP Reader

📂 File:
`packet_analyzer_py/core/pcap_reader.py`

### Purpose

This module reads **network packet capture (PCAP) files** generated by tools such as **Wireshark or tcpdump**.

It parses the PCAP file format and extracts packets sequentially.

---

### Key Structures

```python
@dataclass
class PcapGlobalHeader:
    magic_number: int
    version_major: int
    version_minor: int
    snaplen: int
    network: int
```

This header appears **once at the beginning of the PCAP file**.

---

```python
@dataclass
class PcapPacketHeader:
    ts_sec: int
    ts_usec: int
    incl_len: int
    orig_len: int
```

Each packet in the capture has this header.

---

### Key Functions

```python
reader.open(filename)
```

Opens the PCAP file and validates the global header.

```python
reader.read_next_packet()
```

Reads the next packet and returns a `RawPacket`.

```python
reader.close()
```

Closes the file.

---

# Packet Parser

📂 File:
`packet_analyzer_py/core/packet_parser.py`

### Purpose

Extracts **protocol information** from raw packet bytes.

The parser processes packets layer by layer:

```
Ethernet → IP → TCP/UDP → Payload
```

---

### Main Parsing Function

```python
parsed = PacketParser.parse(raw_packet)
```

Internally this calls several parsing functions:

```python
_parse_ethernet(...)
_parse_ipv4(...)
_parse_tcp(...)
_parse_udp(...)
```

---

### Example: IPv4 Parsing

```python
version_ihl = data[offset]
parsed.ip_version = (version_ihl >> 4) & 0x0F

parsed.ttl = data[offset + 8]
parsed.protocol = data[offset + 9]
```

The parser also extracts:

```
Source IP
Destination IP
Protocol
Ports
TCP flags
Payload
```

---

# SNI Extractor

📂 File:
`packet_analyzer_py/core/sni_extractor.py`

### Purpose

Extracts **domain names from encrypted HTTPS traffic** using **TLS Server Name Indication (SNI)**.

This is the **core Deep Packet Inspection feature** of the project.

---

### TLS SNI Extraction

```python
sni = SNIExtractor.extract(payload)
```

The extractor performs several steps:

1. Verify the packet is a **TLS handshake**
2. Verify the handshake is **ClientHello**
3. Skip session ID, cipher suites, and compression
4. Search for the **SNI extension (0x0000)**
5. Extract the hostname

Example extraction code:

```python
if extension_type == SNIExtractor.EXTENSION_SNI:

    sni_type = payload[offset + 2]
    sni_length = SNIExtractor.read_uint16_be(payload, offset + 3)

    return payload[offset + 5 : offset + 5 + sni_length].decode("utf-8")
```

Example result:

```
www.youtube.com
```

---

# HTTP Host Extraction

For **unencrypted HTTP traffic**, the host is extracted from the request header.

Example:

```python
host = HTTPHostExtractor.extract(payload)
```

Example HTTP request:

```
GET / HTTP/1.1
Host: example.com
```

---

# DNS Query Extraction

DNS packets can also reveal the destination domain.

Example:

```python
domain = DNSExtractor.extract_query(payload)
```

Example DNS query:

```
www.google.com
```

---

# Types Module

📂 File:
`packet_analyzer_py/core/types.py`

### Purpose

Defines shared data structures used across the DPI engine.

---

### FiveTuple (Flow Identifier)

Each network connection is identified using a **five-tuple**.

```python
class FiveTuple:
    src_ip: int
    dst_ip: int
    src_port: int
    dst_port: int
    protocol: int
```

This uniquely identifies a network flow.

Example:

```
192.168.1.100:54321 → 142.250.185.206:443 (TCP)
```

---

### Application Types

Traffic is classified into application categories.

Example:

```
UNKNOWN
HTTP
HTTPS
DNS
GOOGLE
YOUTUBE
FACEBOOK
INSTAGRAM
TIKTOK
```

---

### SNI → Application Mapping

Example classification logic:

```python
if "youtube" in sni:
    return AppType.YOUTUBE

if "facebook" in sni:
    return AppType.FACEBOOK
```

This allows the DPI engine to identify applications based on domain names.

---

# Rule Manager

📂 File:
`packet_analyzer_py/core/rule_manager.py`

### Purpose

Manages **traffic filtering rules** used by the DPI engine.

Supported rule types:

```
IP Blocking
Domain Blocking
Application Blocking
Port Blocking
```

---

### Example Rule Check

```python
block_reason = rules.should_block(
    src_ip,
    dst_port,
    app_type,
    domain
)
```

If a rule matches, the packet is **dropped**.

---

### Example Rules

```
--block-ip 192.168.1.50
--block-app youtube
--block-domain facebook
```

# 8. How SNI Extraction Works

## TLS Handshake

When a user visits a secure website such as:

```
https://www.youtube.com
```

the browser performs a **TLS handshake** with the server before encrypted communication begins.

```
┌──────────┐                              ┌──────────┐
│  Browser │                              │  Server  │
└────┬─────┘                              └────┬─────┘
     │                                         │
     │ ──── Client Hello ─────────────────────►│
     │      (includes SNI: www.youtube.com)    │
     │                                         │
     │ ◄─── Server Hello ───────────────────── │
     │      (includes certificate)             │
     │                                         │
     │ ──── Key Exchange ─────────────────────►│
     │                                         │
     │ ◄═══ Encrypted Data ══════════════════► │
     │      (from here on, everything is       │
     │       encrypted)                        │
```

The **Client Hello** message contains the **Server Name Indication (SNI)** field, which reveals the domain name the client wants to connect to.

Even though HTTPS encrypts application data, the **SNI remains visible during the handshake**.

This allows the DPI engine to identify the destination service.

---

# TLS Client Hello Structure

The TLS Client Hello message contains several fields.

```
Byte 0:     Content Type = 0x16 (Handshake)
Bytes 1-2:  TLS Version
Bytes 3-4:  Record Length

Handshake Layer
---------------
Byte 5:     Handshake Type = 0x01 (Client Hello)
Bytes 6-8:  Handshake Length

Client Hello Body
-----------------
Bytes 9-10:   Client Version
Bytes 11-42:  Random (32 bytes)
Byte 43:      Session ID Length
... Cipher Suites ...
... Compression Methods ...

Extensions
----------
Extension Type (2 bytes)
Extension Length (2 bytes)

SNI Extension (0x0000)
----------------------
SNI List Length
SNI Type = 0x00
SNI Length
SNI Value = "www.youtube.com"
```

The DPI engine scans the extensions section to locate the **SNI extension**.

---

# Python Implementation (Simplified)

The SNI extraction logic is implemented in:

```
packet_analyzer_py/core/sni_extractor.py
```

Example simplified logic:

```python
class SNIExtractor:

    CONTENT_TYPE_HANDSHAKE = 0x16
    HANDSHAKE_CLIENT_HELLO = 0x01
    EXTENSION_SNI = 0x0000

    @staticmethod
    def extract(payload):

        # Verify TLS handshake
        if payload[0] != SNIExtractor.CONTENT_TYPE_HANDSHAKE:
            return None

        # Verify ClientHello
        if payload[5] != SNIExtractor.HANDSHAKE_CLIENT_HELLO:
            return None

        offset = 43

        # Skip Session ID
        session_len = payload[offset]
        offset += 1 + session_len

        # Skip Cipher Suites
        cipher_len = SNIExtractor.read_uint16_be(payload, offset)
        offset += 2 + cipher_len

        # Skip Compression Methods
        comp_len = payload[offset]
        offset += 1 + comp_len

        # Read Extensions Length
        ext_len = SNIExtractor.read_uint16_be(payload, offset)
        offset += 2

        ext_end = offset + ext_len

        # Search extensions for SNI
        while offset + 4 <= ext_end:

            ext_type = SNIExtractor.read_uint16_be(payload, offset)
            ext_length = SNIExtractor.read_uint16_be(payload, offset + 2)
            offset += 4

            if ext_type == SNIExtractor.EXTENSION_SNI:

                sni_length = SNIExtractor.read_uint16_be(payload, offset + 3)

                return payload[offset + 5: offset + 5 + sni_length].decode("utf-8")

            offset += ext_length

        return None
```

---

# Example Result

When the DPI engine processes a TLS Client Hello packet:

```
Client → Server
SNI: www.youtube.com
```

The extractor returns:

```
www.youtube.com
```

The domain is then mapped to an application type:

```
YouTube
Google
Facebook
Twitter
```
---

# 9. How Blocking Works

The DPI engine applies filtering rules to decide whether a packet should be **forwarded** or **dropped**.

Blocking decisions are implemented in:

```
packet_analyzer_py/core/rule_manager.py
```

---

# Rule Types

The engine supports several types of blocking rules.

| Rule Type   | Example        | What it Blocks                        |
| ----------- | -------------- | ------------------------------------- |
| IP          | `192.168.1.50` | All traffic from that source          |
| Application | `YouTube`      | All connections classified as YouTube |
| Domain      | `tiktok`       | Any SNI containing "tiktok"           |
| Port        | `443`          | Traffic targeting that port           |

---

# The Blocking Flow

When a packet arrives, the engine evaluates rules in the following order.

```
Packet arrives
      │
      ▼
┌─────────────────────────────────┐
│ Is source IP in blocked list?  │──Yes──► DROP
└───────────────┬─────────────────┘
                │No
                ▼
┌─────────────────────────────────┐
│ Is destination port blocked?   │──Yes──► DROP
└───────────────┬─────────────────┘
                │No
                ▼
┌─────────────────────────────────┐
│ Is application blocked?        │──Yes──► DROP
└───────────────┬─────────────────┘
                │No
                ▼
┌─────────────────────────────────┐
│ Does domain match blocked list?│──Yes──► DROP
└───────────────┬─────────────────┘
                │No
                ▼
              FORWARD
```

If any rule matches, the packet is **dropped**.

---

# Python Rule Evaluation

The rule evaluation logic is implemented in the `RuleManager` class.

Example code:

```python
def should_block(self, src_ip, dst_port, app, domain):

    if self.is_ip_blocked(src_ip):
        return BlockReason(BlockReasonType.IP, self.ip_to_string(src_ip))

    if self.is_port_blocked(dst_port):
        return BlockReason(BlockReasonType.PORT, str(dst_port))

    if self.is_app_blocked(app):
        return BlockReason(BlockReasonType.APP, app)

    if domain and self.is_domain_blocked(domain):
        return BlockReason(BlockReasonType.DOMAIN, domain)

    return None
```

If the function returns a blocking reason, the flow is marked as **blocked**.

---

# Flow-Based Blocking

The DPI engine blocks traffic at the **flow level**, not the packet level.

A flow is defined by the **five-tuple**:

```
src_ip, dst_ip, src_port, dst_port, protocol
```

Once a flow is identified as blocked, **all future packets belonging to that connection are dropped**.

---

### Example Flow: YouTube Connection

```
Connection:
192.168.1.100:54321 → 142.250.185.206:443
```

Packet sequence:

```
Packet 1 (SYN)          → No SNI yet → FORWARD
Packet 2 (SYN-ACK)      → No SNI yet → FORWARD
Packet 3 (ACK)          → No SNI yet → FORWARD
Packet 4 (Client Hello) → SNI: www.youtube.com
                        → App: YOUTUBE
                        → Rule matched → BLOCK
                        → Packet dropped
Packet 5 (Data)         → Flow already BLOCKED → DROP
Packet 6 (Data)         → Flow already BLOCKED → DROP
```

All subsequent packets in this connection are dropped automatically.

---

# Why Flow-Based Blocking?

The DPI engine cannot identify an application until it sees the **TLS Client Hello packet**, which contains the **SNI field**.

Therefore:

1️⃣ Initial handshake packets must pass through
2️⃣ Once SNI is extracted, the flow is classified
3️⃣ If the rule matches, the entire connection is blocked

This design ensures accurate **application-level filtering for encrypted traffic**.

---

# 11. Understanding the Output

After analyzing a PCAP file, the DPI engine produces two outputs:

1. **Console processing report** from the Python DPI engine
2. **Web dashboard visualization** showing traffic statistics

The filtered packets are also written to a **new PCAP file**.

---

# Example Dashboard Output

After uploading a PCAP file, the web interface displays a summary of the analysis.

Example:

* **Total Packets:** 77
* **Forwarded:** 70
* **Dropped:** 7

These numbers represent how many packets passed or were blocked by the DPI rules.

---

# DPI Engine Console Output

The Python engine also prints a detailed processing report.

Example:

```
╔══════════════════════════════════════════════════════════════╗
║              DPI ENGINE v2.0 (Python Edition)                ║
╚══════════════════════════════════════════════════════════════╝

[DPI] Processing packets...

╔══════════════════════════════════════════════════════════════╗
║                      PROCESSING REPORT                       ║
╠══════════════════════════════════════════════════════════════╣
║ Total Packets:      77                                       ║
║ Forwarded:          70                                       ║
║ Dropped:            7                                        ║
║ Active Flows:       27                                       ║
╠══════════════════════════════════════════════════════════════╣
║                    APPLICATION BREAKDOWN                     ║
╠══════════════════════════════════════════════════════════════╣
║ HTTPS                55  71.4% ################               ║
║ DNS                   4   5.2% #                              ║
║ Twitter/X             3   3.9%                                ║
║ HTTP                  2   2.6%                                ║
║ YouTube               1   1.3%                                ║
║ Facebook              1   1.3%                                ║
║ Instagram             1   1.3%                                ║
║ Amazon                1   1.3%                                ║
║ GitHub                1   1.3%                                ║
║ Discord               1   1.3%                                ║
║ Zoom                  1   1.3%                                ║
║ Telegram              1   1.3%                                ║
║ TikTok                1   1.3%                                ║
║ Spotify               1   1.3%                                ║
║ Cloudflare            1   1.3%                                ║
╚══════════════════════════════════════════════════════════════╝
```

---

# Detected Domains

The DPI engine extracts domains from:

* **TLS SNI**
* **HTTP Host headers**
* **DNS queries**

Example detected domains:

```
[Detected Applications/Domains]

- www.google.com → DNS
- www.youtube.com → YouTube
- www.facebook.com → Facebook
- www.instagram.com → Instagram
- twitter.com → Twitter/X
- www.amazon.com → Amazon
- github.com → GitHub
- discord.com → Discord
- zoom.us → Zoom
- web.telegram.org → Telegram
- www.tiktok.com → TikTok
- open.spotify.com → Spotify
- www.cloudflare.com → Cloudflare
```

---

# What Each Field Means

| Field                     | Meaning                                               |
| ------------------------- | ----------------------------------------------------- |
| **Total Packets**         | Total packets read from the PCAP file                 |
| **Forwarded**             | Packets allowed and written to the output PCAP        |
| **Dropped**               | Packets blocked due to filtering rules                |
| **Active Flows**          | Number of unique network connections detected         |
| **Application Breakdown** | Distribution of traffic across different applications |

---

# Output PCAP File

All allowed packets are written to a new capture file:

```
output_<timestamp>.pcap
```

This file can be opened in:

* **Wireshark**
* **tcpdump**
* **NetworkMiner**

to inspect the filtered network traffic.

---

# Web Dashboard Features

The Node.js web dashboard provides:

* PCAP file upload
* Traffic statistics visualization
* Application detection results
* Rule-based filtering
* DPI engine output logs

Example workflow:

1. Upload a `.pcap` file
2. Configure blocking rules (IP, app, or domain)
3. Run the DPI engine
4. View traffic analysis results in the dashboard

---
---

# 12. Extending the Project

This project can be extended in multiple ways to build a more advanced **network security and traffic analysis system**.

---

# Add More Application Signatures

Currently, applications are identified using **domain pattern matching**.

New applications can easily be added inside:

```
packet_analyzer_py/core/types.py
```

Example:

```python
def sni_to_app_type(sni: str):
    if "youtube" in sni:
        return AppType.YOUTUBE
    if "facebook" in sni:
        return AppType.FACEBOOK
    if "twitch" in sni:
        return AppType.TWITCH
```

This allows the DPI engine to detect additional platforms such as:

* Twitch
* Netflix
* Reddit
* LinkedIn
* Discord

---

# Add Bandwidth Throttling

Instead of dropping packets, traffic can be **rate-limited**.

Example idea:

```python
import time

if should_throttle(flow):
    time.sleep(0.01)  # delay packet
```

This would simulate **traffic shaping**, similar to what ISPs do for streaming or P2P traffic.

---

# Real-Time Traffic Dashboard

The web interface could be extended to show **live statistics**.

Possible features:

* Live packet counters
* Real-time application charts
* Active connection monitoring
* Dynamic rule updates

Example architecture:

```
DPI Engine → WebSocket → Web Dashboard
```

The backend could push updates every second to the UI.

---

# Add QUIC / HTTP3 Support

Modern applications like **YouTube and Google services** increasingly use **QUIC (HTTP/3)**.

Characteristics:

* Runs over **UDP port 443**
* Uses **TLS 1.3 encryption**
* SNI is contained inside QUIC handshake packets

Supporting QUIC would require:

* UDP packet inspection
* QUIC Initial packet parsing
* TLS extension extraction

---

# Persistent Rule Storage

Currently, rules are passed via command line or UI input.

The system could support **persistent rule storage**.

Example idea:

```
rules.json
```

Example content:

```
{
  "blocked_apps": ["youtube", "tiktok"],
  "blocked_domains": ["facebook.com"],
  "blocked_ips": ["192.168.1.50"]
}
```

The DPI engine would load this file at startup.

---

# Possible Advanced Features

Future improvements could include:

* **Machine Learning traffic classification**
* **Anomaly detection**
* **Intrusion detection system (IDS) integration**
* **Packet visualization dashboards**
* **Geo-IP traffic analysis**

---

# Summary

This DPI engine demonstrates several important networking and security concepts:

### Network Protocol Parsing

Understanding how packets are structured across layers:

* Ethernet
* IP
* TCP / UDP
* Application payload

### Deep Packet Inspection

Extracting application information from network traffic, including encrypted connections.

### Flow Tracking

Grouping packets using the **five-tuple** to track network sessions.

### Rule-Based Traffic Filtering

Blocking traffic based on:

* IP addresses
* Applications
* Domain names

### Web-Based Traffic Analysis

A dashboard interface allows users to upload PCAP files and visualize DPI results.

---

# Key Insight

Even though HTTPS encrypts application data, the **TLS handshake exposes the destination domain through SNI (Server Name Indication)**.

This allows network operators to:

* Identify applications
* Monitor traffic usage
* Apply filtering policies

without decrypting the actual payload.




