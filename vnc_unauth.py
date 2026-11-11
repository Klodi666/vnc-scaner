#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║            VNC SCANNER PRO v2.3  —  HACKER EDITION                   ║
║              VNC Detection & Security Auditing Tool                  ║
║                     For AUTHORIZED testing ONLY                      ║
╚══════════════════════════════════════════════════════════════════════╝

Menu:
    1. Scan VNC servers from IP list (TXT file)
    2. Show only VNC servers without authentication
    3. Shodan KEYWORD search -> extract IPs page-by-page
    4. Shodan IP protocol discovery (full service info per IP)
    5. Shodan AUTO-CONFIRM (search + VNC handshake verify)
    6. Shodan IP SCRAPER (all IPs or by country, keyword-driven)
    0. Exit
    d. Toggle debug mode
    h. Help

Requires (only for Options 3-6):
    pip install shodan
"""

import os
import re
import sys
import csv
import time
import socket
import ipaddress
import datetime
import traceback

# ---------------------------------------------------------------------------
# Windows ANSI support
# ---------------------------------------------------------------------------
if os.name == "nt":
    os.system("")

# ---------------------------------------------------------------------------
# Colors (hacker palette)
# ---------------------------------------------------------------------------
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
MAGENTA= "\033[95m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

DEFAULT_PORTS   = [5900, 5901, 5902, 5903]
DEFAULT_TIMEOUT = 5.0

# ---------------------------------------------------------------------------
# Debug system
# ---------------------------------------------------------------------------
DEBUG = False


def debug(*args):
    if DEBUG:
        msg = " ".join(str(a) for a in args)
        print(f"{DIM}{MAGENTA}[DEBUG]{RESET} {DIM}{msg}{RESET}")


def debug_exc(prefix=""):
    if DEBUG:
        print(f"{DIM}{MAGENTA}[DEBUG]{RESET} {RED}{prefix}{RESET}")
        traceback.print_exc()


# ---------------------------------------------------------------------------
# Hacker-style ASCII banner
# ---------------------------------------------------------------------------
BANNER = r"""


██╗░░░██╗███╗░░██╗░█████╗░  ░██████╗░█████╗░░█████╗░███╗░░██╗███╗░░██╗███████╗██████╗░
██║░░░██║████╗░██║██╔══██╗  ██╔════╝██╔══██╗██╔══██╗████╗░██║████╗░██║██╔════╝██╔══██╗
╚██╗░██╔╝██╔██╗██║██║░░╚═╝  ╚█████╗░██║░░╚═╝███████║██╔██╗██║██╔██╗██║█████╗░░██████╔╝
░╚████╔╝░██║╚████║██║░░██╗  ░╚═══██╗██║░░██╗██╔══██║██║╚████║██║╚████║██╔══╝░░██╔══██╗
░░╚██╔╝░░██║░╚███║╚█████╔╝  ██████╔╝╚█████╔╝██║░░██║██║░╚███║██║░╚███║███████╗██║░░██║
░░░╚═╝░░░╚═╝░░╚══╝░╚════╝░  ╚═════╝░░╚════╝░╚═╝░░╚═╝╚═╝░░╚══╝╚═╝░░╚══╝╚══════╝╚═╝░░╚═╝

      ╔════════════════════════════════════════════════════════════════════════╗
      ║            V N C   S C A N N E R   ·   P R O   ·   v 2 . 3             ║
      ║                 Authorized Security Auditing Only                      ║
      ╚════════════════════════════════════════════════════════════════════════╝
"""


# ===========================================================================
# UI helpers
# ===========================================================================
def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def print_banner():
    print(f"{GREEN}{BANNER}{RESET}")


def show_menu():
    dbg_state = f"{MAGENTA}ON{RESET}" if DEBUG else f"{DIM}OFF{RESET}"
    print(f"{BOLD}{CYAN}")
    print(" ╔════════════════════════════════════════════════════════════════╗")
    print(" ║                          MAIN MENU                             ║")
    print(" ╠════════════════════════════════════════════════════════════════╣")
    print(" ║  1. Scan VNC servers from IP list (TXT file)                   ║")
    print(" ║  2. Show only VNC servers without authentication               ║")
    print(" ║  3. Shodan KEYWORD search (extract IPs page-by-page)           ║")
    print(" ║  4. Shodan IP protocol discovery (full service info)           ║")
    print(" ║  5. Shodan AUTO-CONFIRM (search + VNC handshake verify)        ║")
    print(" ║  6. Shodan IP SCRAPER (all IPs / any country by keyword)       ║")
    print(" ║  0. Exit                                                       ║")
    print(" ╠════════════════════════════════════════════════════════════════╣")
    print(f" ║  d. Toggle debug mode [{dbg_state}{CYAN}]      h. Help                          ║")
    print(" ╚════════════════════════════════════════════════════════════════╝")
    print(f"{RESET}")


# ===========================================================================
# RFB protocol helpers
# ===========================================================================
def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        try:
            chunk = sock.recv(n - len(data))
        except socket.timeout:
            debug("recv_exact: timeout")
            return None
        except (ConnectionResetError, ConnectionAbortedError, OSError) as e:
            debug(f"recv_exact: socket error {e}")
            return None
        if not chunk:
            debug(f"recv_exact: connection closed at {len(data)}/{n} bytes")
            return None
        data += chunk
    return data


def read_reason(sock):
    length_data = recv_exact(sock, 4)
    if length_data is None:
        return None
    length = int.from_bytes(length_data, "big")
    debug(f"read_reason: length={length}")
    if 0 < length < 65536:
        reason = recv_exact(sock, length)
        if reason:
            return reason.decode("utf-8", errors="ignore")
    return None


def read_server_init(sock):
    header = recv_exact(sock, 24)
    if header is None:
        return None
    name_len = int.from_bytes(header[20:24], "big")
    debug(f"read_server_init: name_len={name_len}")
    if 0 < name_len < 65536:
        name = recv_exact(sock, name_len)
        if name:
            return {"name": name.decode("utf-8", errors="ignore")}
    return {"name": ""}


# ===========================================================================
# VNC check (full RFB handshake)
# ===========================================================================
def check_vnc(ip, port, timeout=DEFAULT_TIMEOUT):
    debug(f"check_vnc: attempting {ip}:{port} (timeout={timeout}s)")
    result = {
        "ip": ip, "port": port, "vnc": False, "auth": None,
        "vulnerable": False, "version": None, "desktop_name": None,
        "status": "unknown", "error": None,
        "timestamp": datetime.datetime.now().isoformat(timespec="seconds"),
    }

    sock = None
    try:
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        debug(f"check_vnc: TCP connected to {ip}:{port}")

        banner = recv_exact(sock, 12)
        if banner is None or len(banner) < 12:
            result["status"] = "uncertain"
            result["error"] = "No/short banner"
            return result

        debug(f"check_vnc: banner={banner!r}")
        if not banner.startswith(b"RFB "):
            result["status"] = "not_vnc"
            result["error"] = "No RFB banner"
            return result

        result["vnc"] = True
        version_str = banner.decode("ascii", errors="ignore").strip()
        result["version"] = version_str

        m = re.match(r"RFB (\d+)\.(\d+)", version_str)
        if m:
            major, minor = int(m.group(1)), int(m.group(2))
        else:
            major, minor = 3, 8
        if major != 3:
            major, minor = 3, 8
        if minor < 3:
            minor = 3
        if minor > 8:
            minor = 8

        debug(f"check_vnc: negotiated RFB {major}.{minor}")
        if minor >= 8:
            client_ver = b"RFB 003.008\n"
            use_modern = True
        elif minor >= 7:
            client_ver = b"RFB 003.007\n"
            use_modern = True
        else:
            client_ver = b"RFB 003.003\n"
            use_modern = False

        sock.sendall(client_ver)

        if use_modern:
            n_data = recv_exact(sock, 1)
            if n_data is None:
                result["status"] = "uncertain"
                result["error"] = "Handshake closed at security types"
                return result

            n_types = n_data[0]
            debug(f"check_vnc: server offered {n_types} security type(s)")
            if n_types == 0:
                reason = read_reason(sock)
                result["auth"] = "required"
                result["status"] = "auth_required"
                result["error"] = reason or "No security types offered"
                return result

            types_data = recv_exact(sock, n_types)
            if types_data is None:
                result["status"] = "uncertain"
                result["error"] = "Failed to read security types"
                return result

            offered = list(types_data)
            debug(f"check_vnc: security types offered = {offered}")
            if 1 not in offered:
                result["auth"] = "required"
                result["status"] = "auth_required"
                result["error"] = f"No None-auth. Offered: {offered}"
                return result

            sock.sendall(b"\x01")
            sec_result = recv_exact(sock, 4)
            if sec_result is None:
                result["status"] = "uncertain"
                result["error"] = "No security result"
                return result

            code = int.from_bytes(sec_result, "big")
            debug(f"check_vnc: SecurityResult code={code}")
            if code != 0:
                result["auth"] = "required"
                result["status"] = "auth_required"
                if minor >= 8:
                    reason = read_reason(sock)
                    result["error"] = reason or "Security failed"
                return result

            result["auth"] = "none"
            result["vulnerable"] = True
            result["status"] = "vulnerable"
            init = read_server_init(sock)
            if init:
                result["desktop_name"] = init.get("name") or None
        else:
            sec_type_data = recv_exact(sock, 4)
            if sec_type_data is None:
                result["status"] = "uncertain"
                result["error"] = "No security type (3.3)"
                return result

            sec_type = int.from_bytes(sec_type_data, "big")
            debug(f"check_vnc: RFB 3.3 security type = {sec_type}")
            if sec_type == 0:
                reason = read_reason(sock)
                result["auth"] = "required"
                result["status"] = "auth_required"
                result["error"] = reason or "Connection failed"
            elif sec_type == 1:
                result["auth"] = "none"
                result["vulnerable"] = True
                result["status"] = "vulnerable"
                init = read_server_init(sock)
                if init:
                    result["desktop_name"] = init.get("name") or None
            elif sec_type == 2:
                result["auth"] = "required"
                result["status"] = "auth_required"
                result["error"] = "VNC Authentication required"
            else:
                result["auth"] = "required"
                result["status"] = "auth_required"
                result["error"] = f"Unknown security type {sec_type}"

    except socket.timeout:
        result["status"] = "timeout"
        result["error"] = "Connection timeout"
    except ConnectionRefusedError:
        result["status"] = "closed"
        result["error"] = "Connection refused"
    except socket.gaierror as e:
        result["status"] = "error"
        result["error"] = f"Address error: {e}"
    except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError) as e:
        result["status"] = "closed"
        result["error"] = f"Connection reset/aborted: {e}"
    except OSError as e:
        result["status"] = "error"
        result["error"] = f"Network error: {e}"
    except Exception as e:
        result["status"] = "error"
        result["error"] = f"Error: {e}"
        debug_exc("check_vnc unexpected error")
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass

    return result


# ===========================================================================
# Result printing / report writing
# ===========================================================================
def print_result(idx, total, r):
    prefix = f"{DIM}[{idx:04d}/{total:04d}]{RESET} "
    ip_port = f"{r['ip']}:{r['port']}"
    status = r["status"]

    if status == "vulnerable":
        extra = ""
        if r.get("version"):
            extra = f" ({r['version']}"
            if r.get("desktop_name"):
                extra += f" - {r['desktop_name']}"
            extra += ")"
        print(f"{prefix}{GREEN}[+] {ip_port} - VNC NO AUTHENTICATION - CONFIRMED{extra}{RESET}")
    elif status == "auth_required":
        print(f"{prefix}{RED}[-] {ip_port} - VNC AUTH REQUIRED - NOT VULNERABLE{RESET}")
    elif status == "not_vnc":
        print(f"{prefix}{RED}[-] {ip_port} - NOT VNC - NOT VULNERABLE{RESET}")
    elif status == "closed":
        print(f"{prefix}{RED}[-] {ip_port} - PORT CLOSED - NOT VULNERABLE{RESET}")
    elif status == "timeout":
        print(f"{prefix}{YELLOW}[!] {ip_port} - TIMEOUT{RESET}")
    elif status == "uncertain":
        print(f"{prefix}{YELLOW}[!] {ip_port} - UNCERTAIN ({r.get('error') or '?'}){RESET}")
    else:
        print(f"{prefix}{YELLOW}[!] {ip_port} - ERROR ({r.get('error') or '?'}){RESET}")


def write_report_header(fh):
    fh.write("# VNC Scanner Pro - Scan Report\n")
    fh.write(f"# Generated: {datetime.datetime.now().isoformat(timespec='seconds')}\n")
    fh.write("# Format: TIMESTAMP | IP | PORT | VNC | AUTH | RFB_VERSION | DESKTOP_NAME | STATUS\n")
    fh.write("# STATUS: VULNERABLE, AUTH_REQUIRED, NOT_VNC, CLOSED, TIMEOUT, UNCERTAIN, ERROR\n")
    fh.flush()


def write_report_line(fh, r):
    vnc = "YES" if r["vnc"] else "NO"
    auth = r["auth"] or "-"
    version = (r["version"] or "-").replace("|", "/")
    desktop = (r["desktop_name"] or "-").replace("|", "/")
    status = r["status"].upper()
    line = (
        f"{r['timestamp']} | {r['ip']} | {r['port']} | {vnc} | {auth} | "
        f"{version} | {desktop} | {status}\n"
    )
    fh.write(line)
    fh.flush()


def parse_report_line(line):
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    parts = [p.strip() for p in line.split("|")]
    if len(parts) < 8:
        return None
    return {
        "timestamp": parts[0], "ip": parts[1], "port": parts[2],
        "vnc": parts[3], "auth": parts[4], "version": parts[5],
        "desktop": parts[6], "status": parts[7],
    }


# ===========================================================================
# Target parsing (now strips "| metadata" so Option 3/5/6 output is reusable)
# ===========================================================================
def parse_target(line, ports):
    line = line.strip()
    if not line or line.startswith("#"):
        return []

    # Strip trailing metadata after '|' (Option 3/5/6 output format)
    if "|" in line:
        line = line.split("|", 1)[0].strip()
        if not line:
            return []

    if line.startswith("["):
        close = line.find("]")
        if close > 0:
            ip_part = line[1:close]
            rest = line[close + 1:]
            try:
                ipaddress.IPv6Address(ip_part)
            except ValueError:
                return []
            if rest.startswith(":"):
                try:
                    port = int(rest[1:])
                    if 1 <= port <= 65535:
                        return [(ip_part, port)]
                except ValueError:
                    return []
                return []
            return [(ip_part, p) for p in ports]

    if line.count(":") > 1:
        try:
            ipaddress.IPv6Address(line)
            return [(line, p) for p in ports]
        except ValueError:
            return []

    if ":" in line:
        ip_part, port_part = line.rsplit(":", 1)
        try:
            ipaddress.IPv4Address(ip_part)
            port = int(port_part)
            if 1 <= port <= 65535:
                return [(ip_part, port)]
        except (ValueError, IndexError):
            return []
        return []

    try:
        ipaddress.IPv4Address(line)
        return [(line, p) for p in ports]
    except ValueError:
        return []


def dedupe_targets(targets):
    seen = set()
    out = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


# ===========================================================================
# Option 1 – Scan IPs from TXT
# ===========================================================================
def option1_scan():
    print(f"\n{BOLD}{GREEN}=== Option 1: Scan VNC Servers from IP List ==={RESET}\n")
    debug("option1: entered")

    path = input(f"{CYAN}Enter path to IP list TXT file: {RESET}").strip()
    if not path:
        print(f"{RED}[!] No path provided.{RESET}")
        return
    if not os.path.isfile(path):
        print(f"{RED}[!] File not found: {path}{RESET}")
        return

    custom = input(
        f"{CYAN}Additional ports (comma separated, blank = default 5900-5903): {RESET}"
    ).strip()
    ports = list(DEFAULT_PORTS)
    if custom:
        try:
            for p in custom.split(","):
                p = p.strip()
                if not p:
                    continue
                v = int(p)
                if 1 <= v <= 65535 and v not in ports:
                    ports.append(v)
            ports = sorted(set(ports))
        except ValueError:
            print(f"{YELLOW}[!] Invalid port list, using default ports.{RESET}")

    targets = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                targets.extend(parse_target(line, ports))
    except Exception as e:
        print(f"{RED}[!] Failed to read file: {e}{RESET}")
        debug_exc("option1 read file")
        return

    targets = dedupe_targets(targets)
    if not targets:
        print(f"{RED}[!] No valid IP addresses found in file.{RESET}")
        return

    print(f"{GREEN}[*] Loaded {len(targets)} unique target(s) to scan.{RESET}")

    timeout_str = input(
        f"{CYAN}Connection timeout in seconds (default 5): {RESET}"
    ).strip()
    try:
        timeout = float(timeout_str) if timeout_str else DEFAULT_TIMEOUT
        if timeout <= 0:
            timeout = DEFAULT_TIMEOUT
    except ValueError:
        timeout = DEFAULT_TIMEOUT

    out_path = input(
        f"{CYAN}Enter output TXT file path (e.g. /home/ghost/Desktop/vnc_results.txt): {RESET}"
    ).strip()
    if not out_path:
        print(f"{RED}[!] No output path provided.{RESET}")
        return

    out_dir = os.path.dirname(out_path)
    if out_dir and not os.path.isdir(out_dir):
        try:
            os.makedirs(out_dir, exist_ok=True)
        except Exception as e:
            print(f"{RED}[!] Cannot create output directory: {e}{RESET}")
            return

    print(f"\n{GREEN}[*] Starting scan...{RESET}\n")

    total = len(targets)
    vuln_count = auth_count = other_count = 0

    try:
        fh = open(out_path, "w", encoding="utf-8")
    except Exception as e:
        print(f"{RED}[!] Cannot open output file: {e}{RESET}")
        return

    try:
        write_report_header(fh)
        for idx, (ip, port) in enumerate(targets, 1):
            r = check_vnc(ip, port, timeout=timeout)
            print_result(idx, total, r)
            write_report_line(fh, r)
            if r["status"] == "vulnerable":
                vuln_count += 1
            elif r["status"] == "auth_required":
                auth_count += 1
            else:
                other_count += 1
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Scan interrupted by user. Partial results preserved.{RESET}")
    finally:
        try:
            fh.close()
        except Exception:
            pass

    print(f"\n{BOLD}{GREEN}=== Scan Summary ==={RESET}")
    print(f"{GREEN}Vulnerable (no auth): {vuln_count}{RESET}")
    print(f"{RED}Auth required:        {auth_count}{RESET}")
    print(f"{YELLOW}Other (closed/error): {other_count}{RESET}")
    print(f"{CYAN}Report saved to: {out_path}{RESET}")


# ===========================================================================
# Option 2 – Filter previous report for unauthenticated VNC
# ===========================================================================
def option2_show_vuln():
    print(f"\n{BOLD}{GREEN}=== Option 2: Show Only Unauthenticated VNC ==={RESET}\n")

    path = input(f"{CYAN}Enter path to previous scan report: {RESET}").strip()
    if not path or not os.path.isfile(path):
        print(f"{RED}[!] File not found: {path}{RESET}")
        return

    vulnerable = []
    seen = set()
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                parsed = parse_report_line(line)
                if not parsed:
                    continue
                if parsed["status"].upper() == "VULNERABLE":
                    key = (parsed["ip"], parsed["port"])
                    if key not in seen:
                        seen.add(key)
                        vulnerable.append(key)
    except Exception as e:
        print(f"{RED}[!] Failed to read report: {e}{RESET}")
        return

    if not vulnerable:
        print(f"{YELLOW}[!] No unauthenticated VNC servers found in report.{RESET}")
        return

    print(f"\n{GREEN}{BOLD}CONFIRMED UNAUTHENTICATED VNC:{RESET}\n")
    for ip, port in vulnerable:
        print(f"{GREEN}  {ip}:{port}{RESET}")
    print(f"\n{GREEN}{BOLD}TOTAL: {len(vulnerable)}{RESET}")

    if input(f"\n{CYAN}Export this list to TXT? (y/n): {RESET}").strip().lower() != "y":
        return

    out_path = input(f"{CYAN}Output TXT path: {RESET}").strip()
    if not out_path:
        return

    out_dir = os.path.dirname(out_path)
    if out_dir and not os.path.isdir(out_dir):
        try:
            os.makedirs(out_dir, exist_ok=True)
        except Exception as e:
            print(f"{RED}[!] Cannot create directory: {e}{RESET}")
            return

    try:
        with open(out_path, "w", encoding="utf-8") as f:
            f.write("# Confirmed Unauthenticated VNC Servers\n")
            f.write(f"# Generated: {datetime.datetime.now().isoformat(timespec='seconds')}\n")
            f.write("# Format: IP:PORT\n")
            for ip, port in vulnerable:
                f.write(f"{ip}:{port}\n")
        print(f"{GREEN}[+] Exported {len(vulnerable)} entries to {out_path}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Export failed: {e}{RESET}")


# ===========================================================================
# Option 3 – Shodan KEYWORD search (page-by-page IP extraction)
# ===========================================================================
def option3_shodan():
    print(f"\n{BOLD}{GREEN}=== Option 3: Shodan Keyword Search (IP extraction) ==={RESET}\n")

    try:
        import shodan
    except ImportError:
        print(f"{RED}[!] Shodan library not installed.{RESET}")
        print(f"{YELLOW}    Install with: pip install shodan{RESET}")
        return

    api_key = input(f"{CYAN}Enter your Shodan API key: {RESET}").strip()
    if not api_key:
        print(f"{RED}[!] No API key.{RESET}")
        return

    try:
        api = shodan.Shodan(api_key)
        info = api.info()
        print(f"{GREEN}[*] API plan: {info.get('plan', '?')} | "
              f"Query credits: {info.get('query_credits', '?')}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Shodan API error (check key): {e}{RESET}")
        return

    print(f"{DIM}  Examples: 'vnc', 'port:5900', 'product:RealVNC', "
          f"'vnc country:US'{RESET}")
    query = input(f"{CYAN}Enter Shodan keyword / query (default 'vnc'): {RESET}").strip()
    if not query:
        query = "vnc"

    per_page_str = input(
        f"{CYAN}Results per page (default 50, max 100): {RESET}"
    ).strip()
    try:
        per_page = int(per_page_str) if per_page_str else 50
    except ValueError:
        per_page = 50
    per_page = max(1, min(per_page, 100))

    pages_str = input(
        f"{CYAN}Number of pages to search (default 10): {RESET}"
    ).strip()
    try:
        num_pages = int(pages_str) if pages_str else 10
    except ValueError:
        num_pages = 10
    num_pages = max(1, num_pages)

    print(f"{YELLOW}[!] This will make up to {num_pages} Shodan search call(s) "
          f"(~{num_pages} query credit(s)){RESET}")

    out_path = input(
        f"{CYAN}Output TXT path (e.g. /home/ghost/Desktop/shodan_ips.txt): {RESET}"
    ).strip()
    if not out_path:
        print(f"{RED}[!] No output path.{RESET}")
        return

    out_dir = os.path.dirname(out_path)
    if out_dir and not os.path.isdir(out_dir):
        try:
            os.makedirs(out_dir, exist_ok=True)
        except Exception as e:
            print(f"{RED}[!] Cannot create directory: {e}{RESET}")
            return

    try:
        fh = open(out_path, "w", encoding="utf-8")
        fh.write("# Shodan Keyword Search — IP Extraction\n")
        fh.write(f"# Query: {query}\n")
        fh.write(f"# Generated: {datetime.datetime.now().isoformat(timespec='seconds')}\n")
        fh.write("# Format: IP:PORT | PRODUCT | VERSION | ORG | COUNTRY\n")
        fh.flush()
    except Exception as e:
        print(f"{RED}[!] Cannot open output file: {e}{RESET}")
        return

    seen = set()
    unique_results = []
    total_matches_seen = 0
    vnc_ports = (5900, 5901, 5902, 5903, 5904, 5905)

    print(f"\n{GREEN}[*] Searching Shodan: '{query}' — "
          f"{num_pages} page(s) × {per_page} per page{RESET}\n")

    try:
        for page in range(1, num_pages + 1):
            print(f"{DIM}  [Page {page}/{num_pages}] querying Shodan...{RESET}",
                  end=" ", flush=True)
            try:
                resp = api.search(query, page=page, limit=per_page)
            except Exception as e:
                print(f"{YELLOW}error: {e}{RESET}")
                debug_exc("option3 page search")
                break

            matches = resp.get("matches", [])
            total_api = resp.get("total", 0)
            print(f"{GREEN}{len(matches)} match(es){RESET} "
                  f"{DIM}(total on Shodan: {total_api}){RESET}")

            if not matches:
                print(f"{DIM}  No more results on page {page}, stopping.{RESET}")
                break

            for banner in matches:
                ip = banner.get("ip_str")
                port = banner.get("port")
                if not ip or not port:
                    continue
                key = (ip, port)
                total_matches_seen += 1
                if key in seen:
                    continue
                seen.add(key)

                loc = banner.get("location", {})
                country = loc.get("country_name", "") if isinstance(loc, dict) else ""
                product = banner.get("product", "") or ""
                version = banner.get("version", "") or ""
                org = banner.get("org", "") or ""

                unique_results.append({
                    "ip": ip, "port": port, "product": product,
                    "version": version, "org": org, "country": country,
                })

                fh.write(f"{ip}:{port} | {product} | {version} | {org} | {country}\n")
                fh.flush()

                color = GREEN if port in vnc_ports else CYAN
                print(f"    {color}{ip}:{port:<6}{RESET} "
                      f"{DIM}{(product or '-')[:20]:<20} "
                      f"{(org or '-')[:25]:<25} {country}{RESET}")

            if page < num_pages:
                time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Search interrupted by user. "
              f"Partial results preserved.{RESET}")
    finally:
        try:
            fh.close()
        except Exception:
            pass

    print(f"\n{GREEN}{BOLD}═══ SUMMARY ═══{RESET}")
    print(f"  Matches seen (with dupes): {total_matches_seen}")
    print(f"  Unique IP:PORT entries:    {GREEN}{len(unique_results)}{RESET}")
    print(f"  Saved to:                  {CYAN}{out_path}{RESET}")

    if not unique_results:
        return

    if input(f"\n{CYAN}Also export as CSV? (y/n): {RESET}").strip().lower() == "y":
        csv_path = input(f"{CYAN}CSV output path: {RESET}").strip()
        if csv_path:
            csv_dir = os.path.dirname(csv_path)
            if csv_dir and not os.path.isdir(csv_dir):
                try:
                    os.makedirs(csv_dir, exist_ok=True)
                except Exception as e:
                    print(f"{RED}[!] Cannot create dir: {e}{RESET}")
                    return
            try:
                with open(csv_path, "w", newline="", encoding="utf-8") as cf:
                    w = csv.writer(cf)
                    w.writerow(["IP", "PORT", "PRODUCT", "VERSION", "ORG", "COUNTRY"])
                    for r in unique_results:
                        w.writerow([r["ip"], r["port"], r["product"],
                                    r["version"], r["org"], r["country"]])
                print(f"{GREEN}[+] CSV exported to {csv_path}{RESET}")
            except Exception as e:
                print(f"{RED}[!] CSV export failed: {e}{RESET}")


# ===========================================================================
# Option 4 – Shodan IP protocol discovery
# ===========================================================================
PORT_FALLBACK = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 5900: "vnc", 5901: "vnc", 5902: "vnc",
    5903: "vnc", 5904: "vnc", 5905: "vnc", 6379: "redis",
    8080: "http", 8443: "https", 9200: "elasticsearch", 27017: "mongodb",
}


def determine_protocol(service):
    shodan_meta = service.get("_shodan", {})
    if isinstance(shodan_meta, dict):
        module = shodan_meta.get("module", "")
        if module:
            return module.lower()

    product = (service.get("product") or "").lower()
    hints = {
        "vnc": "vnc", "nginx": "http", "apache": "http", "http": "http",
        "openssh": "ssh", "ssh": "ssh", "ftp": "ftp", "smtp": "smtp",
        "mysql": "mysql", "postgres": "postgresql", "redis": "redis",
        "rdp": "rdp", "telnet": "telnet",
    }
    for key, val in hints.items():
        if key in product:
            return val

    port = service.get("port")
    if port in PORT_FALLBACK:
        return PORT_FALLBACK[port]

    data = (service.get("data") or "")[:40].upper()
    if data.startswith("RFB "):
        return "vnc"
    if data.startswith("SSH-"):
        return "ssh"
    if data.startswith("HTTP/") or "HTTP/" in data:
        return "http"
    if data.startswith("220 ") and "FTP" in data:
        return "ftp"
    if data.startswith("220 ") and "SMTP" in data:
        return "smtp"

    return "tcp"


def protocol_color(proto):
    if proto == "vnc":
        return GREEN
    if proto in ("http", "https"):
        return CYAN
    if proto in ("ssh", "telnet", "ftp", "smtp", "rdp", "smb"):
        return YELLOW
    return ""


def option4_shodan_protocols():
    print(f"\n{BOLD}{GREEN}=== Option 4: Shodan IP Protocol Discovery ==={RESET}\n")

    try:
        import shodan
    except ImportError:
        print(f"{RED}[!] Shodan library not installed. "
              f"pip install shodan{RESET}")
        return

    api_key = input(f"{CYAN}Enter your Shodan API key: {RESET}").strip()
    if not api_key:
        return

    try:
        api = shodan.Shodan(api_key)
        info = api.info()
        print(f"{GREEN}[*] API plan: {info.get('plan', '?')}  "
              f"| Query credits: {info.get('query_credits', '?')}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Shodan API error: {e}{RESET}")
        return

    target = input(
        f"{CYAN}Enter IP, CIDR, or Shodan query "
        f"(e.g. 1.2.3.4 / 1.2.3.0/24 / 'port:5900 country:US'): {RESET}"
    ).strip()
    if not target:
        return

    single_ip = None
    search_query = None
    try:
        single_ip = str(ipaddress.ip_address(target))
    except ValueError:
        try:
            ipaddress.ip_network(target, strict=False)
            search_query = f"net:{target}"
        except ValueError:
            search_query = target

    if single_ip:
        target_ips = [single_ip]
        print(f"{GREEN}[*] Target IP: {single_ip}{RESET}")
    else:
        print(f"{GREEN}[*] Searching Shodan: {search_query}{RESET}")
        target_ips = []
        try:
            for banner in api.search_cursor(search_query):
                ip = banner.get("ip_str")
                if ip and ip not in target_ips:
                    target_ips.append(ip)
        except KeyboardInterrupt:
            print(f"\n{YELLOW}[!] Search interrupted.{RESET}")
            return
        except Exception as e:
            print(f"{RED}[!] Search error: {e}{RESET}")
            return

        if not target_ips:
            print(f"{YELLOW}[!] No IPs found.{RESET}")
            return

        print(f"{GREEN}[*] Found {len(target_ips)} unique IP(s){RESET}")
        limit_str = input(
            f"{CYAN}Max IPs to inspect (default 25, 1 credit each): {RESET}"
        ).strip()
        try:
            limit = int(limit_str) if limit_str else 25
        except ValueError:
            limit = 25
        target_ips = target_ips[:max(1, limit)]

    all_results = []
    for idx, ip in enumerate(target_ips, 1):
        print(f"{DIM}  [{idx}/{len(target_ips)}] Fetching {ip}...{RESET}")
        try:
            host_info = api.host(ip)
        except shodan.APIError as e:
            if "No information" not in str(e):
                print(f"{YELLOW}[!] API error for {ip}: {e}{RESET}")
            continue
        except Exception as e:
            print(f"{YELLOW}[!] Error for {ip}: {e}{RESET}")
            continue

        for svc in host_info.get("data", []):
            proto = determine_protocol(svc)
            all_results.append({
                "ip": ip, "port": svc.get("port"),
                "transport": svc.get("transport", "tcp"),
                "protocol": proto,
                "product": svc.get("product", "") or "",
                "version": svc.get("version", "") or "",
                "org": host_info.get("org", "") or "",
                "country": host_info.get("country_name", "") or "",
                "hostnames": ", ".join(host_info.get("hostnames", [])[:2]),
                "banner": (svc.get("data") or "").split("\n")[0][:120],
                "timestamp": datetime.datetime.now().isoformat(timespec="seconds"),
            })

    if not all_results:
        print(f"{YELLOW}[!] No services found.{RESET}")
        return

    by_ip = {}
    for r in all_results:
        by_ip.setdefault(r["ip"], []).append(r)

    print(f"\n{GREEN}{BOLD}╔════════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{GREEN}{BOLD}║              PROTOCOL DISCOVERY RESULTS                        ║{RESET}")
    print(f"{GREEN}{BOLD}╚════════════════════════════════════════════════════════════════╝{RESET}\n")

    for ip in sorted(by_ip.keys(), key=lambda x: (x.count(".") > 0, x)):
        services = by_ip[ip]
        org = services[0].get("org", "")
        country = services[0].get("country", "")
        header = f"{CYAN}{BOLD}{ip}{RESET}"
        if org or country:
            header += f" {DIM}({org} / {country}){RESET}"
        print(header)
        print(f"  {DIM}{'PORT/PROTO':<14} {'SERVICE':<12} {'PRODUCT':<24} {'VERSION':<15} BANNER{RESET}")
        print(f"  {DIM}{'-'*104}{RESET}")
        for svc in sorted(services, key=lambda s: (s["port"] or 0)):
            color = protocol_color(svc["protocol"])
            print(
                f"  {color}{svc['port']}/{svc['transport']:<10}{RESET} "
                f"{color}{svc['protocol']:<12}{RESET} "
                f"{(svc['product'] or '-')[:22]:<24} "
                f"{(svc['version'] or '-')[:13]:<15} "
                f"{DIM}{svc['banner']}{RESET}"
            )
        print()

    vnc_services = sum(1 for r in all_results if r["protocol"] == "vnc")
    http_services = sum(1 for r in all_results if r["protocol"] in ("http", "https"))
    print(f"{GREEN}{BOLD}═══ SUMMARY ═══{RESET}")
    print(f"  IPs analyzed:    {CYAN}{len(by_ip)}{RESET}")
    print(f"  Total services:  {len(all_results)}")
    print(f"  VNC services:    {GREEN}{vnc_services}{RESET}")
    print(f"  HTTP/HTTPS:      {CYAN}{http_services}{RESET}")

    if input(f"\n{CYAN}Export results? (y/n): {RESET}").strip().lower() != "y":
        return

    fmt = input(f"{CYAN}Format (txt/csv/both): {RESET}").strip().lower()

    if fmt in ("txt", "both"):
        p = input(f"{CYAN}TXT output path: {RESET}").strip()
        if p:
            try:
                with open(p, "w", encoding="utf-8") as f:
                    f.write("# Shodan IP Protocol Discovery\n")
                    f.write(f"# Generated: {datetime.datetime.now().isoformat(timespec='seconds')}\n")
                    for r in all_results:
                        f.write(
                            f"{r['ip']} | {r['port']} | {r['transport']} | {r['protocol']} | "
                            f"{r['product']} | {r['version']} | {r['org']} | {r['country']} | {r['banner']}\n"
                        )
                print(f"{GREEN}[+] TXT exported to {p}{RESET}")
            except Exception as e:
                print(f"{RED}[!] TXT export failed: {e}{RESET}")

    if fmt in ("csv", "both"):
        p = input(f"{CYAN}CSV output path: {RESET}").strip()
        if p:
            try:
                with open(p, "w", newline="", encoding="utf-8") as f:
                    w = csv.writer(f)
                    w.writerow(["IP", "PORT", "TRANSPORT", "SERVICE", "PRODUCT",
                                "VERSION", "ORG", "COUNTRY", "BANNER", "TIMESTAMP"])
                    for r in all_results:
                        w.writerow([r["ip"], r["port"], r["transport"], r["protocol"],
                                    r["product"], r["version"], r["org"],
                                    r["country"], r["banner"], r["timestamp"]])
                print(f"{GREEN}[+] CSV exported to {p}{RESET}")
            except Exception as e:
                print(f"{RED}[!] CSV export failed: {e}{RESET}")


# ===========================================================================
# Option 5 – Shodan AUTO-CONFIRM
# ===========================================================================
def option5_auto_confirm():
    print(f"\n{BOLD}{GREEN}=== Option 5: Shodan AUTO-CONFIRM ==={RESET}\n")
    print(f"{DIM}  Shodan search → real VNC handshake verify → confirmed vulnerable list{RESET}\n")

    try:
        import shodan
    except ImportError:
        print(f"{RED}[!] Shodan library not installed. "
              f"pip install shodan{RESET}")
        return

    api_key = input(f"{CYAN}Enter your Shodan API key: {RESET}").strip()
    if not api_key:
        return

    try:
        api = shodan.Shodan(api_key)
        info = api.info()
        print(f"{GREEN}[*] API plan: {info.get('plan', '?')} | "
              f"Query credits: {info.get('query_credits', '?')}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Shodan API error: {e}{RESET}")
        return

    query = input(
        f"{CYAN}Shodan keyword / query (default 'port:5900 vnc'): {RESET}"
    ).strip() or "port:5900 vnc"

    per_page_str = input(
        f"{CYAN}Results per page (default 50, max 100): {RESET}"
    ).strip()
    try:
        per_page = int(per_page_str) if per_page_str else 50
    except ValueError:
        per_page = 50
    per_page = max(1, min(per_page, 100))

    pages_str = input(
        f"{CYAN}Number of pages to search (default 10): {RESET}"
    ).strip()
    try:
        num_pages = int(pages_str) if pages_str else 10
    except ValueError:
        num_pages = 10
    num_pages = max(1, num_pages)

    timeout_str = input(
        f"{CYAN}Handshake timeout in seconds (default 5): {RESET}"
    ).strip()
    try:
        hs_timeout = float(timeout_str) if timeout_str else DEFAULT_TIMEOUT
    except ValueError:
        hs_timeout = DEFAULT_TIMEOUT

    full_path = input(
        f"{CYAN}Full report path: {RESET}"
    ).strip()
    vuln_path = input(
        f"{CYAN}Vulnerable-only path: {RESET}"
    ).strip()
    if not full_path or not vuln_path:
        print(f"{RED}[!] Both paths required.{RESET}")
        return

    for p in (full_path, vuln_path):
        d = os.path.dirname(p)
        if d and not os.path.isdir(d):
            try:
                os.makedirs(d, exist_ok=True)
            except Exception as e:
                print(f"{RED}[!] Cannot create {d}: {e}{RESET}")
                return

    print(f"\n{YELLOW}[!] ~{num_pages} query credit(s) + 1 handshake per IP{RESET}\n")

    print(f"{GREEN}{BOLD}── Phase 1: Shodan search ──{RESET}\n")
    candidates = []
    seen = set()

    try:
        for page in range(1, num_pages + 1):
            print(f"{DIM}  [Page {page}/{num_pages}]{RESET} ", end="", flush=True)
            try:
                resp = api.search(query, page=page, limit=per_page)
            except Exception as e:
                print(f"{YELLOW}error: {e}{RESET}")
                break

            matches = resp.get("matches", [])
            print(f"{GREEN}{len(matches)} match(es){RESET}")
            if not matches:
                break

            for banner in matches:
                ip = banner.get("ip_str")
                port = banner.get("port")
                if not ip or not port:
                    continue
                key = (ip, port)
                if key in seen:
                    continue
                seen.add(key)
                loc = banner.get("location", {})
                country = loc.get("country_name", "") if isinstance(loc, dict) else ""
                candidates.append({
                    "ip": ip, "port": port,
                    "product": banner.get("product", "") or "",
                    "org": banner.get("org", "") or "",
                    "country": country,
                })
            if page < num_pages:
                time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Shodan phase interrupted.{RESET}")
        if not candidates:
            return

    if not candidates:
        print(f"{YELLOW}[!] No candidates.{RESET}")
        return

    print(f"\n{GREEN}[*] {len(candidates)} unique IP:PORT candidate(s){RESET}")
    print(f"\n{GREEN}{BOLD}── Phase 2: VNC handshake verify ──{RESET}\n")

    try:
        full_fh = open(full_path, "w", encoding="utf-8")
        vuln_fh = open(vuln_path, "w", encoding="utf-8")
    except Exception as e:
        print(f"{RED}[!] Cannot open output: {e}{RESET}")
        return

    write_report_header(full_fh)
    full_fh.write(f"# Shodan query: {query}\n")
    full_fh.write(f"# Shodan candidates: {len(candidates)}\n")
    full_fh.flush()

    vuln_fh.write("# CONFIRMED UNAUTHENTICATED VNC (from Shodan auto-confirm)\n")
    vuln_fh.write(f"# Shodan query: {query}\n")
    vuln_fh.write(f"# Generated: {datetime.datetime.now().isoformat(timespec='seconds')}\n")
    vuln_fh.write("# Format: IP:PORT\n")
    vuln_fh.flush()

    total = len(candidates)
    vuln_count = auth_count = other_count = 0

    try:
        for idx, cand in enumerate(candidates, 1):
            r = check_vnc(cand["ip"], cand["port"], timeout=hs_timeout)
            print_result(idx, total, r)

            vnc_flag = "YES" if r["vnc"] else "NO"
            auth = r["auth"] or "-"
            version = (r["version"] or "-").replace("|", "/")
            desktop = (r["desktop_name"] or "-").replace("|", "/")
            status = r["status"].upper()
            full_fh.write(
                f"{r['timestamp']} | {r['ip']} | {r['port']} | {vnc_flag} | {auth} | "
                f"{version} | {desktop} | {status} | "
                f"SHODAN: {cand['product'] or '-'} | {cand['org'] or '-'} | {cand['country'] or '-'}\n"
            )
            full_fh.flush()

            if r["status"] == "vulnerable":
                vuln_count += 1
                vuln_fh.write(f"{r['ip']}:{r['port']}\n")
                vuln_fh.flush()
            elif r["status"] == "auth_required":
                auth_count += 1
            else:
                other_count += 1
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Handshake interrupted. Partial results preserved.{RESET}")
    finally:
        try:
            full_fh.close()
        except Exception:
            pass
        try:
            vuln_fh.close()
        except Exception:
            pass

    print(f"\n{GREEN}{BOLD}═══ AUTO-CONFIRM SUMMARY ═══{RESET}")
    print(f"  Shodan candidates:        {total}")
    print(f"  {GREEN}Confirmed vulnerable:     {vuln_count}{RESET}")
    print(f"  {RED}Auth required:            {auth_count}{RESET}")
    print(f"  {YELLOW}Other:                    {other_count}{RESET}")
    print(f"\n  Full report:              {CYAN}{full_path}{RESET}")
    print(f"  Vulnerable-only list:     {GREEN}{vuln_path}{RESET}")

    if vuln_count > 0:
        print(f"\n{GREEN}{BOLD}CONFIRMED UNAUTHENTICATED VNC ({vuln_count}):{RESET}")
        try:
            with open(vuln_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        print(f"  {GREEN}{line}{RESET}")
        except Exception:
            pass


# ===========================================================================
# Option 6 – Shodan IP SCRAPER (all IPs or by country, keyword-driven)
# ===========================================================================
def option6_shodan_scraper():
    print(f"\n{BOLD}{GREEN}=== Option 6: Shodan IP SCRAPER ==={RESET}\n")
    print(f"{DIM}  Scrape ALL IPs matching a keyword, or pick a specific country{RESET}\n")

    try:
        import shodan
    except ImportError:
        print(f"{RED}[!] Shodan library not installed. "
              f"pip install shodan{RESET}")
        return

    # --- 1) API key --------------------------------------------------------
    api_key = input(f"{CYAN}Enter your Shodan API key: {RESET}").strip()
    if not api_key:
        print(f"{RED}[!] No API key.{RESET}")
        return

    try:
        api = shodan.Shodan(api_key)
        info = api.info()
        plan = info.get("plan", "?")
        query_credits = info.get("query_credits", "?")
        print(f"{GREEN}[*] API plan: {plan} | Query credits: {query_credits}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Shodan API error: {e}{RESET}")
        return

    # --- 2) Keyword --------------------------------------------------------
    print(f"{DIM}  Examples: 'vnc', 'port:5900', 'apache', 'nginx', 'rdp'{RESET}")
    print(f"{DIM}  For VNC-only results use: 'port:5900' or 'vnc'{RESET}")
    keyword = input(f"{CYAN}Enter keyword / query (required): {RESET}").strip()
    if not keyword:
        print(f"{RED}[!] Keyword required.{RESET}")
        return

    # --- 3) Probe: total + country facets ---------------------------------
    print(f"\n{GREEN}[*] Analyzing query to find countries...{RESET}")
    try:
        probe = api.search(keyword, page=1, limit=1, facets={"country": 20})
    except Exception as e:
        print(f"{RED}[!] Failed to analyze query: {e}{RESET}")
        return

    total_matches = probe.get("total", 0)
    facets = probe.get("facets", {}).get("country", []) or []

    if total_matches == 0:
        print(f"{YELLOW}[!] No results for '{keyword}'.{RESET}")
        return

    print(f"{GREEN}[*] Total matches on Shodan: {total_matches:,}{RESET}")

    # --- 4) Country selection ---------------------------------------------
    country_code = None
    if facets:
        print(f"\n{CYAN}Top countries for this query:{RESET}")
        for i, f in enumerate(facets, 1):
            bar_len = min(30, max(1, int(f["count"] / max(1, facets[0]["count"]) * 30)))
            bar = "█" * bar_len
            print(f"  {DIM}[{i:2d}]{RESET} {f['value']} — {f['count']:>10,}  "
                  f"{GREEN}{bar}{RESET}")
        print(f"  {DIM}[ 0]{RESET} ALL countries (no filter)")

        print(f"\n{DIM}Pick a number, type a 2-letter country code (US, DE, FR...), "
              f"or 0 for ALL:{RESET}")
        choice = input(f"{CYAN}Selection: {RESET}").strip()

        if choice in ("", "0"):
            country_code = None
        elif choice.isdigit() and 1 <= int(choice) <= len(facets):
            country_code = facets[int(choice) - 1]["value"]
        elif len(choice) == 2 and choice.isalpha():
            country_code = choice.upper()
        elif choice.isalpha() and len(choice) > 2:
            country_code = choice.upper()  # trust user, e.g. they typed "US"
        else:
            country_code = choice.upper()

    final_query = keyword if not country_code else f"{keyword} country:{country_code}"
    print(f"\n{GREEN}[*] Final query: {CYAN}{final_query}{RESET}")
    if country_code:
        print(f"{GREEN}[*] Country filter: {country_code}{RESET}")
    else:
        print(f"{GREEN}[*] Country filter: ALL{RESET}")

    # --- 5) Pagination settings -------------------------------------------
    per_page = 100           # Shodan API maximum
    max_pages_shodan = 100   # Shodan API hard cap on the public tier

    pages_str = input(
        f"\n{CYAN}Max pages to scrape (default 50, max {max_pages_shodan}, "
        f"{per_page} results/page): {RESET}"
    ).strip()
    try:
        num_pages = int(pages_str) if pages_str else 50
    except ValueError:
        num_pages = 50
    num_pages = max(1, min(num_pages, max_pages_shodan))

    expected_max = num_pages * per_page
    print(f"{YELLOW}[!] Up to {num_pages} page(s) ≈ {expected_max:,} IP:PORT candidates{RESET}")
    print(f"{YELLOW}[!] ~{num_pages} query credit(s) will be consumed{RESET}")

    if isinstance(query_credits, int) and query_credits < num_pages:
        print(f"{RED}[!] WARNING: You only have {query_credits} query credit(s)!{RESET}")
        if input(f"{YELLOW}Continue anyway? (y/n): {RESET}").strip().lower() != "y":
            return

    # --- 6) Output path ----------------------------------------------------
    out_path = input(
        f"\n{CYAN}Output TXT path (e.g. /home/ghost/Desktop/scraped_ips.txt): {RESET}"
    ).strip()
    if not out_path:
        print(f"{RED}[!] No output path.{RESET}")
        return

    out_dir = os.path.dirname(out_path)
    if out_dir and not os.path.isdir(out_dir):
        try:
            os.makedirs(out_dir, exist_ok=True)
        except Exception as e:
            print(f"{RED}[!] Cannot create directory: {e}{RESET}")
            return

    try:
        fh = open(out_path, "w", encoding="utf-8")
        fh.write("# Shodan IP Scraper — Option 6\n")
        fh.write(f"# Keyword: {keyword}\n")
        fh.write(f"# Country filter: {country_code or 'ALL'}\n")
        fh.write(f"# Full query: {final_query}\n")
        fh.write(f"# Total on Shodan: {total_matches}\n")
        fh.write(f"# Generated: {datetime.datetime.now().isoformat(timespec='seconds')}\n")
        fh.write("# Format: IP:PORT | PRODUCT | VERSION | ORG | COUNTRY\n")
        fh.flush()
    except Exception as e:
        print(f"{RED}[!] Cannot open output: {e}{RESET}")
        return

    # --- 7) Scrape ---------------------------------------------------------
    print(f"\n{GREEN}{BOLD}── Scraping: {final_query} ──{RESET}\n")

    seen = set()
    unique = []
    pages_done = 0
    country_stats = {}

    try:
        for page in range(1, num_pages + 1):
            print(f"{DIM}  [Page {page}/{num_pages}]{RESET} ", end="", flush=True)
            try:
                resp = api.search(final_query, page=page, limit=per_page)
            except Exception as e:
                print(f"{YELLOW}error: {e}{RESET}")
                debug_exc("option6 page")
                break

            matches = resp.get("matches", [])
            if not matches:
                print(f"{DIM}no more results, stopping.{RESET}")
                break

            new_on_page = 0
            for banner in matches:
                ip = banner.get("ip_str")
                port = banner.get("port")
                if not ip or not port:
                    continue
                key = (ip, port)
                if key in seen:
                    continue
                seen.add(key)
                new_on_page += 1

                loc = banner.get("location", {})
                country = loc.get("country_name", "") if isinstance(loc, dict) else ""
                country_stats[country] = country_stats.get(country, 0) + 1
                product = banner.get("product", "") or ""
                version = banner.get("version", "") or ""
                org = banner.get("org", "") or ""

                unique.append({
                    "ip": ip, "port": port, "product": product,
                    "version": version, "org": org, "country": country,
                })

                fh.write(f"{ip}:{port} | {product} | {version} | {org} | {country}\n")

            fh.flush()
            pages_done += 1
            print(f"{GREEN}+{new_on_page} new{RESET} "
                  f"{DIM}(unique total: {len(unique):,}){RESET}")

            if page < num_pages:
                time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Scrape interrupted. Partial results saved.{RESET}")
    finally:
        try:
            fh.close()
        except Exception:
            pass

    # --- 8) Summary --------------------------------------------------------
    print(f"\n{GREEN}{BOLD}═══ SCRAPE SUMMARY ═══{RESET}")
    print(f"  Query:           {CYAN}{final_query}{RESET}")
    print(f"  Pages scraped:   {pages_done}/{num_pages}")
    print(f"  Unique IP:PORT:  {GREEN}{len(unique):,}{RESET}")
    print(f"  Saved to:        {CYAN}{out_path}{RESET}")

    if country_stats:
        print(f"\n{CYAN}Countries collected (top 10):{RESET}")
        for c, n in sorted(country_stats.items(), key=lambda x: -x[1])[:10]:
            print(f"  {c or '-'}: {n:,}")

    # --- 9) Optional CSV ---------------------------------------------------
    if unique and input(f"\n{CYAN}Also export as CSV? (y/n): {RESET}").strip().lower() == "y":
        csv_path = input(f"{CYAN}CSV output path: {RESET}").strip()
        if csv_path:
            csv_dir = os.path.dirname(csv_path)
            if csv_dir and not os.path.isdir(csv_dir):
                try:
                    os.makedirs(csv_dir, exist_ok=True)
                except Exception as e:
                    print(f"{RED}[!] Cannot create dir: {e}{RESET}")
                    return
            try:
                with open(csv_path, "w", newline="", encoding="utf-8") as cf:
                    w = csv.writer(cf)
                    w.writerow(["IP", "PORT", "PRODUCT", "VERSION", "ORG", "COUNTRY"])
                    for r in unique:
                        w.writerow([r["ip"], r["port"], r["product"],
                                    r["version"], r["org"], r["country"]])
                print(f"{GREEN}[+] CSV exported to {csv_path}{RESET}")
            except Exception as e:
                print(f"{RED}[!] CSV failed: {e}{RESET}")


# ===========================================================================
# Help
# ===========================================================================
def print_help():
    print(f"""
{BOLD}VNC SCANNER PRO v2.3 — HELP{RESET}

{CYAN}Option 1 — Scan TXT list:{RESET}
  • Accepts IPv4, IPv6, IP:PORT, [IPv6]:PORT
  • Lines starting with '#' are ignored
  • Also accepts metadata from Options 3/5/6 output ("IP:PORT | ...")
  • Default ports: 5900-5903 (custom ports optional)
  • Scans one-by-one, in file order, live results
  • Report saved progressively (safe to Ctrl+C)

{CYAN}Option 2 — Filter previous report:{RESET}
  • Reads report from Option 1 / Option 5
  • Shows ONLY confirmed unauth VNC servers (GREEN)
  • Optional TXT export

{CYAN}Option 3 — Shodan KEYWORD search:{RESET}
  • Prompts: keyword, results-per-page, pages, output path
  • Saves IP:PORT | PRODUCT | VERSION | ORG | COUNTRY
  • Optional CSV export
  • 1 query credit per page

{CYAN}Option 4 — Shodan IP protocol discovery:{RESET}
  • For each IP: fetch full host info, show every service/protocol
  • Export TXT and/or CSV
  • 1 host credit per IP inspected

{CYAN}Option 5 — Shodan AUTO-CONFIRM:{RESET}
  • Full pipeline: Shodan search → real VNC handshake verify
  • Saves TWO files: full report + vulnerable-only list
  • Safe to Ctrl+C

{CYAN}Option 6 — Shodan IP SCRAPER:{RESET}
  • Enter keyword, script auto-detects top countries via Shodan facets
  • Pick ALL countries or a specific one (number or 2-letter code)
  • Scrapes page-by-page (default 50 pages × 100 = ~5,000 IPs)
  • Saves IP:PORT | PRODUCT | VERSION | ORG | COUNTRY
  • Progressive save — safe to Ctrl+C
  • Optional CSV export
  • Each page = 1 query credit (hard-capped at 100 pages by Shodan)

{CYAN}Debug mode (d):{RESET}
  • Toggle at menu with 'd' or start with --debug
  • Prints internal steps, RFB negotiation details, tracebacks

{CYAN}Report format (Option 1 / Option 5):{RESET}
  TIMESTAMP | IP | PORT | VNC | AUTH | VERSION | DESKTOP | STATUS

{CYAN}Status values:{RESET}
  VULNERABLE / AUTH_REQUIRED / NOT_VNC / CLOSED / TIMEOUT / UNCERTAIN / ERROR

{YELLOW}This tool is for authorized security testing only.{RESET}
""")


# ===========================================================================
# Main
# ===========================================================================
def main():
    global DEBUG

    if len(sys.argv) > 1:
        args = sys.argv[1:]
        if "-h" in args or "--help" in args:
            print_help()
            return
        if "-d" in args or "--debug" in args:
            DEBUG = True
            print(f"{MAGENTA}[DEBUG] Debug mode enabled via CLI.{RESET}")

    try:
        clear_screen()
        print_banner()
        while True:
            show_menu()
            choice = input(f"{BOLD}{GREEN}root@vnc-scanner:~# {RESET}").strip().lower()

            if choice in ("0", "exit", "quit", "q"):
                print(f"{GREEN}[*] Shutting down. Stay legal. Goodbye.{RESET}")
                break
            elif choice == "1":
                option1_scan()
            elif choice == "2":
                option2_show_vuln()
            elif choice == "3":
                option3_shodan()
            elif choice == "4":
                option4_shodan_protocols()
            elif choice == "5":
                option5_auto_confirm()
            elif choice == "6":
                option6_shodan_scraper()
            elif choice in ("d", "debug"):
                DEBUG = not DEBUG
                state = f"{MAGENTA}ON{RESET}" if DEBUG else f"{DIM}OFF{RESET}"
                print(f"{GREEN}[*] Debug mode toggled: {state}")
            elif choice in ("h", "help", "?"):
                print_help()
            else:
                print(f"{YELLOW}[!] Invalid choice.{RESET}")

            if choice not in ("0", "exit", "quit", "q"):
                input(f"\n{DIM}Press Enter to return to menu...{RESET}")
                clear_screen()
                print_banner()
    except KeyboardInterrupt:
        print(f"\n{GREEN}[*] Interrupted. Goodbye.{RESET}")


if __name__ == "__main__":
    main()