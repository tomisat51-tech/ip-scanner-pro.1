#!/usr/bin/env python3
"""IP Scanner Pro — TCP port scanner with service detection."""

import socket
import concurrent.futures
import argparse
import sys
import time
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
    22:   b"",   # SSH sends banner on connect
    21:   b"",   # FTP sends banner on connect
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
        return {"port": port, "open": False}


def parse_ports(spec: str) -> list[int]:
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
        ip = socket.gethostbyname(host)
        return ip
    except socket.gaierror as e:
        print(f"{RED}Cannot resolve {host!r}: {e}{RESET}")
        sys.exit(1)


def print_header(host: str, ip: str, ports: list[int]):
    print()
    print(f"{BOLD}{CYAN}╔══════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║          IP Scanner Pro — Port Check             ║{RESET}")
    print(f"{BOLD}{CYAN}╚══════════════════════════════════════════════════╝{RESET}")
    print(f"  Target : {BOLD}{host}{RESET}" + (f"  ({ip})" if ip != host else ""))
    print(f"  Ports  : {len(ports)} port(s) — {', '.join(map(str, ports))}")
    print(f"  Time   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()


def print_results(results: list[dict]):
    open_ports  = [r for r in results if r["open"]]
    closed_ports = [r for r in results if not r["open"]]

    print(f"  {'PORT':<8} {'STATE':<10} {'SERVICE':<22} {'LATENCY':>9}  BANNER")
    print(f"  {'-'*7}  {'-'*9}  {'-'*21}  {'-'*9}  {'-'*30}")

    for r in sorted(results, key=lambda x: x["port"]):
        if r["open"]:
            state   = f"{GREEN}OPEN{RESET}"
            service = r.get("service", "unknown")
            latency = f"{r['latency_ms']:.1f} ms"
            banner  = r.get("banner", "")
            banner_str = f"{DIM}{banner[:50]}{RESET}" if banner else ""
            print(f"  {r['port']:<8} {state:<19} {service:<22} {latency:>9}  {banner_str}")
        else:
            state = f"{RED}closed{RESET}"
            print(f"  {r['port']:<8} {state:<19} {DIM}—{RESET}")

    print()
    print(f"  {BOLD}Summary:{RESET}  {GREEN}{len(open_ports)} open{RESET}  |  {len(closed_ports)} closed")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="IP Scanner Pro — scan TCP ports on a host",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  python3 scanner.py localhost 7799,5055,8123,1984,5050
  python3 scanner.py 192.168.1.1 80,443,22
  python3 scanner.py example.com 1-1000 --threads 200
""",
    )
    parser.add_argument("host", help="hostname or IP address")
    parser.add_argument(
        "ports",
        help="ports: single (80), list (80,443), range (1-1024), or 'common'",
    )
    parser.add_argument("-t", "--timeout",  type=float, default=1.0, metavar="SEC",
                        help="connection timeout per port (default: 1.0)")
    parser.add_argument("-T", "--threads",  type=int,   default=100, metavar="N",
                        help="parallel threads (default: 100)")
    parser.add_argument("--no-banner", action="store_true",
                        help="skip banner grabbing")
    args = parser.parse_args()

    COMMON = "21,22,23,25,53,80,110,143,443,445,1984,3000,3306,3389,5000,5050,5055,5432,5900,6379,7799,8000,8080,8123,8443,8888,9090,9200,27017"

    port_spec = COMMON if args.ports == "common" else args.ports
    ports = parse_ports(port_spec)

    ip = resolve_host(args.host)
    print_header(args.host, ip, ports)

    grab = not args.no_banner

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {ex.submit(scan_port, ip, p, args.timeout, grab): p for p in ports}
        done = 0
        total = len(futures)
        for fut in concurrent.futures.as_completed(futures):
            done += 1
            print(f"\r  Scanning... {done}/{total}", end="", flush=True)
            results.append(fut.result())

    print("\r" + " " * 30 + "\r", end="")
    print_results(results)


if __name__ == "__main__":
    main()
