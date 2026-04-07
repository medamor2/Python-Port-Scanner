#!/usr/bin/env python3
"""
Port Scanner

"""

from __future__ import annotations

import argparse
import ipaddress
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 8080]
KNOWN_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt",
}


def validate_target_ip(value: str) -> str:

    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"Invalid IP address: {value}") from exc


def parse_ports(raw_ports: str | None) -> list[int]:

    if not raw_ports:
        return COMMON_PORTS.copy()

    parsed: set[int] = set()
    for chunk in raw_ports.split(","):
        part = chunk.strip()
        if not part:
            continue

        if "-" in part:
            left, right = part.split("-", 1)
            start = int(left)
            end = int(right)
            if start > end:
                start, end = end, start
            for port in range(start, end + 1):
                if 1 <= port <= 65535:
                    parsed.add(port)
        else:
            port = int(part)
            if 1 <= port <= 65535:
                parsed.add(port)

    return sorted(parsed)


def detect_service(sock: socket.socket, port: int) -> str:

    try:
        service = socket.getservbyport(port)
    except OSError:
        service = KNOWN_SERVICES.get(port, "unknown")

    banner = ""
    try:
        sock.settimeout(0.6)
        sock.sendall(b"\r\n")
        data = sock.recv(64)
        banner = data.decode(errors="ignore").strip().replace("\n", " ")
    except (socket.timeout, OSError):
        pass

    if banner:
        return f"{service} | banner: {banner[:40]}"
    return service


def scan_port(target_ip: str, port: int, timeout: float = 1.0) -> tuple[int, str] | None:

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            service = detect_service(sock, port)
            return port, service
    return None


def run_scan(target_ip: str, ports: list[int], workers: int, timeout: float) -> list[tuple[int, str]]:

    open_ports: list[tuple[int, str]] = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(scan_port, target_ip, port, timeout) for port in ports]
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    open_ports.sort(key=lambda x: x[0])
    return open_ports


def print_results(target_ip: str, scanned_ports: list[int], open_ports: list[tuple[int, str]], elapsed: float) -> None:

    print("=" * 68)
    print("Simple Port Scanner Report")
    print("=" * 68)
    print(f"Target IP     : {target_ip}")
    print(f"Ports scanned : {len(scanned_ports)}")
    print(f"Elapsed time  : {elapsed:.2f} sec")
    print("-" * 68)

    if not open_ports:
        print("No open ports found in the selected range/list.")
        print("=" * 68)
        return

    print(f"{'PORT':<10}{'STATE':<10}{'SERVICE'}")
    print("-" * 68)
    for port, service in open_ports:
        print(f"{port:<10}{'OPEN':<10}{service}")
    print("=" * 68)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Beginner-friendly Python port scanner with basic service detection."
    )
    parser.add_argument(
        "target",
        type=validate_target_ip,
        help="Target IPv4/IPv6 address to scan (example: 192.168.1.10)",
    )
    parser.add_argument(
        "--ports",
        type=str,
        default=None,
        help="Comma-separated ports or ranges (example: 21,22,80,443 or 1-1024)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=100,
        help="Number of threads for concurrent scanning (default: 100)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Socket timeout in seconds (default: 1.0)",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    try:
        ports = parse_ports(args.ports)
    except ValueError:
        parser.error("Invalid port list. Use values like 80,443 or ranges like 1-1024.")

    if not ports:
        parser.error("No valid ports to scan.")

    workers = max(1, min(args.workers, 1000))
    timeout = max(0.1, args.timeout)

    start = time.perf_counter()
    open_ports = run_scan(args.target, ports, workers, timeout)
    elapsed = time.perf_counter() - start

    print_results(args.target, ports, open_ports, elapsed)


if __name__ == "__main__":
    main()
