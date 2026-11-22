#!/usr/bin/env python3
"""IP Scanner Pro — TCP port scanner with service detection, OS guess, JSON/CSV export."""

import socket
import concurrent.futures
import argparse
import sys
import time
import json
import csv
import io
import subprocess
from datetime import datetime

KNOWN_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    1984: "Redis/Custom", 3000: "Node.js/Dev", 3306: "MySQL",
    3389: "RDP", 4040: "Ngrok", 5000: "Flask/Dev", 5050: "PostgreSQL/Custom",
    5055: "Custom", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    7799: "Custom", 8000: "HTTP-Alt", 8080: "HTTP-Proxy",
    8123: "Home Assistant / Custom", 8443: "HTTPS-Alt", 8888: "Jupyter",
    9090: "Prometheus", 9200: "Elasticsearch", 27017: "MongoDB",
}

BANNER_PROBES = {
    80:   b"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n",
    8000: b"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n",
    8123: b"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n",
    22:   b"",
    21:   b"",
}

RESET  = "\033[0m"
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"


def grab_banner(host: str, port: int, timeout: float = 2.0) -> str:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            probe = BANNER_PROBES.get(port, b"")
            if probe:
                s.sendall(probe.replace(b"{host}", host.encode()))
            s.settimeout(timeout)
            try:
                data = s.recv(1024)
                banner = data.decode("utf-8", errors="replace").strip()
                first_line = banner.splitlines()[0][:80] if banner else ""
                return first_line
            except (socket.timeout, OSError):
                return ""
    except Exception:
        return ""


def scan_port(host: str, port: int, timeout: float, grab: bool) -> dict:
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            latency = (time.monotonic() - start) * 1000
            banner = grab_banner(host, port, timeout) if grab else ""
            service = KNOWN_SERVICES.get(port, "unknown")
            return {"port": port, "open": True, "latency_ms": round(latency, 1),
                    "service": service, "banner": banner}
    except (ConnectionRefusedError, socket.timeout, OSError):
        return {"port": port, "open": False, "latency_ms": None,
                "service": KNOWN_SERVICES.get(port, "unknown"), "banner": ""}


def detect_os(host: str) -> dict:
    """Guess OS from ICMP TTL value via ping."""
    try:
        out = subprocess.check_output(
            ["ping", "-c", "1", "-W", "2", host],
            stderr=subprocess.DEVNULL, timeout=5
        ).decode()
        for line in out.splitlines():
            if "ttl=" in line.lower():
                ttl_str = [p for p in line.split() if "ttl=" in p.lower()][0]
                ttl = int(ttl_str.split("=")[1])
                if ttl <= 64:
                    guess = "Linux / macOS / Android"
                elif ttl <= 128:
                    guess = "Windows"
                elif ttl <= 255:
                    guess = "Cisco / FreeBSD / Solaris"
                else:
                    guess = "Unknown"
                return {"reachable": True, "ttl": ttl, "os_guess": guess}
        return {"reachable": True, "ttl": None, "os_guess": "Unknown"}
    except Exception:
        return {"reachable": False, "ttl": None, "os_guess": "Host unreachable"}


def parse_ports(spec: str) -> list:
    ports = []
    for part in spec.split(","):
        part = part.strip()
        if "-" in part and not part.startswith("-"):
            lo, hi = part.split("-", 1)
            ports.extend(range(int(lo), int(hi) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def resolve_host(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except socket.gaierror as e:
        print(f"{RED}Cannot resolve {host!r}: {e}{RESET}")
        sys.exit(1)


def to_json(host, ip, os_info, results, scanned_at) -> str:
    return json.dumps({
        "host": host, "ip": ip, "scanned_at": scanned_at,
        "os_detection": os_info,
        "ports": results,
    }, indent=2)


def to_csv(results) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=["port", "open", "service", "latency_ms", "banner"])
    w.writeheader()
    for r in sorted(results, key=lambda x: x["port"]):
        w.writerow(r)
    return buf.getvalue()


def print_header(host, ip, ports, os_info):
    print()
    print(f"{BOLD}{CYAN}╔══════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║          IP Scanner Pro — Port Check             ║{RESET}")
    print(f"{BOLD}{CYAN}╚══════════════════════════════════════════════════╝{RESET}")
    print(f"  Target : {BOLD}{host}{RESET}" + (f"  ({ip})" if ip != host else ""))
    print(f"  Ports  : {len(ports)} port(s)")
    print(f"  Time   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    if os_info["reachable"]:
        ttl_str = f"TTL={os_info['ttl']}" if os_info["ttl"] else ""
        print(f"  OS     : {YELLOW}{os_info['os_guess']}{RESET}  {DIM}{ttl_str}{RESET}")
    else:
        print(f"  OS     : {RED}{os_info['os_guess']}{RESET}")
    print()


def print_results(results):
    open_ports   = [r for r in results if r["open"]]
    closed_ports = [r for r in results if not r["open"]]

    print(f"  {'PORT':<8} {'STATE':<10} {'SERVICE':<22} {'LATENCY':>9}  BANNER")
    print(f"  {'-'*7}  {'-'*9}  {'-'*21}  {'-'*9}  {'-'*36}")

    for r in sorted(results, key=lambda x: x["port"]):
        if r["open"]:
            state   = f"{GREEN}OPEN{RESET}"
            latency = f"{r['latency_ms']:.1f} ms"
            banner  = r.get("banner", "")
            banner_str = f"{DIM}{banner[:50]}{RESET}" if banner else ""
            print(f"  {r['port']:<8} {state:<19} {r['service']:<22} {latency:>9}  {banner_str}")
        else:
            state = f"{RED}closed{RESET}"
            print(f"  {r['port']:<8} {state:<19} {DIM}{r['service']}{RESET}")

    print()
    print(f"  {BOLD}Summary:{RESET}  {GREEN}{len(open_ports)} open{RESET}  |  {len(closed_ports)} closed")
    print()


COMMON = "21,22,23,25,53,80,110,143,443,445,1984,3000,3306,3389,5000,5050,5055,5432,5900,6379,7799,8000,8080,8123,8443,8888,9090,9200,27017"


def run_scan(host, port_spec, timeout=1.0, threads=100, grab=True):
    ports = parse_ports(COMMON if port_spec == "common" else port_spec)
    ip = resolve_host(host)
    os_info = detect_os(ip)
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(scan_port, ip, p, timeout, grab): p for p in ports}
        done, total = 0, len(futures)
        for fut in concurrent.futures.as_completed(futures):
            done += 1
            print(f"\r  Scanning... {done}/{total}", end="", flush=True)
            results.append(fut.result())
    print("\r" + " " * 30 + "\r", end="")
    return ip, os_info, results


def main():
    parser = argparse.ArgumentParser(
        description="IP Scanner Pro",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  python3 scanner.py 192.168.1.31 7799,5055,8123,1984,5050
  python3 scanner.py 192.168.1.31 common
  python3 scanner.py 192.168.1.31 1-1024 --threads 300 --json results.json
  python3 scanner.py 192.168.1.31 80,443 --csv results.csv
""",
    )
    parser.add_argument("host")
    parser.add_argument("ports", help="ports / 'common' / range e.g. 1-1024")
    parser.add_argument("-t", "--timeout",   type=float, default=1.0)
    parser.add_argument("-T", "--threads",   type=int,   default=100)
    parser.add_argument("--no-banner",       action="store_true")
    parser.add_argument("--json",            metavar="FILE", help="save results as JSON")
    parser.add_argument("--csv",             metavar="FILE", help="save results as CSV")
    args = parser.parse_args()

    ip, os_info, results = run_scan(
        args.host, args.ports, args.timeout, args.threads, not args.no_banner
    )
    scanned_at = datetime.now().isoformat()

    print_header(args.host, ip, results, os_info)
    print_results(results)

    if args.json:
        with open(args.json, "w") as f:
            f.write(to_json(args.host, ip, os_info, results, scanned_at))
        print(f"  {GREEN}JSON saved:{RESET} {args.json}")

    if args.csv:
        with open(args.csv, "w") as f:
            f.write(to_csv(results))
        print(f"  {GREEN}CSV saved:{RESET} {args.csv}")


if __name__ == "__main__":
    main()
