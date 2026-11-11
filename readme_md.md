# ╔══════════════════════════════════════════════════════════════════════╗
# ║            VNC SCANNER PRO v2.3  —  HACKER EDITION                   ║
# ╚══════════════════════════════════════════════════════════════════════╝

> **VNC Detection & Security Auditing Tool**  
> *For AUTHORIZED testing and network security assessments only.*

---

## 🚀 Features

* **Option 1: TXT List Scanner** — Scan custom IP lists (supports IPv4, IPv6, `IP:PORT`, and `[IPv6]:PORT`) across default or custom ports with progressive file saving.
* **Option 2: Unauthenticated Filter** — Filter and review previous scan reports to isolate confirmed vulnerable unauthenticated VNC servers.
* **Option 3: Shodan Keyword Search** — Page-by-page IP extraction using custom Shodan queries with metadata tracking.
* **Option 4: Shodan Protocol Discovery** — Deep-dive service and protocol inspection for individual IPs, CIDR ranges, or queries.
* **Option 5: Shodan Auto-Confirm** — Automated pipeline that combines Shodan searching with live VNC RFB handshake verification to isolate open doors.
* **Option 6: Shodan IP Scraper** — Keyword-driven mass scraper with automatic country facet analysis, allowing global scraping or single-country filtering (US, DE, FR, etc.).
* **Debug Mode (`-d`)** — Detailed protocol negotiation logging and traceback diagnostics.

---

## ⚙️ Requirements & Installation

The core scanner works out-of-the-box with Python 3. Shodan integration (Options 3–6) requires the official Shodan Python library.

1. **Clone or download the script:**
   ```bash
   git clone https://github.com/Klodi666/vnc-scanner-pro.git
   cd vnc-scanner-pro
   ```

2. **Install dependencies (required for Shodan options):**
   ```bash
   pip install shodan
   ```

---

## 🕹️ Usage

Run the script directly from your terminal:

```bash
python3 vnctool.py
```

To launch immediately with **Debug Mode** enabled:
```bash
python3 vnctool.py --debug
```

### Main Menu Overview
```text
 ╔════════════════════════════════════════════════════════════════╗
 ║                          MAIN MENU                             ║
 ╠════════════════════════════════════════════════════════════════╣
 ║  1. Scan VNC servers from IP list (TXT file)                   ║
 ║  2. Show only VNC servers without authentication               ║
 ║  3. Shodan KEYWORD search (extract IPs page-by-page)           ║
 ║  4. Shodan IP protocol discovery (full service info)           ║
 ║  5. Shodan AUTO-CONFIRM (search + VNC handshake verify)        ║
 ║  6. Shodan IP SCRAPER (all IPs / any country by keyword)       ║
 ║  0. Exit                                                       ║
 ╠════════════════════════════════════════════════════════════════╣
 ║  d. Toggle debug mode                  h. Help                 ║
 ╚════════════════════════════════════════════════════════════════╝
```

---

## 📂 Report Formats

* **Scan / Auto-Confirm Reports:** Saved in a clean pipe-delimited format:
  ```text
  TIMESTAMP | IP | PORT | VNC | AUTH | RFB_VERSION | DESKTOP_NAME | STATUS
  ```
* **Scraper / Search Reports (`Options 3 & 6`):**
  ```text
  IP:PORT | PRODUCT | VERSION | ORG | COUNTRY
  ```

---

## ⚖️ Legal Disclaimer

> **Disclaimer:** This tool is created strictly for educational purposes, authorized security auditing, and penetration testing evaluations. The author is not responsible for any misuse or damage caused by this program. Ensure you have explicit written permission from system owners before testing network targets.
