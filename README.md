#  Python Port Scanner

A networking and cybersecurity project that scans a target IP address, checks common ports, and prints open ports with basic service detection.

## Features

- Scan a target IP address
- Check common ports by default (including 21, 22, 80, 443)
- Display open ports in a clean output table
- Use multithreading for faster scanning
- Perform basic service detection

## Why Ports Matter

A port is a communication endpoint on a device.

- Port 21 (FTP): file transfer service
- Port 22 (SSH): secure remote access
- Port 80 (HTTP): web traffic
- Port 443 (HTTPS): encrypted web traffic

Open ports can be normal and required for services, but unnecessary open ports can increase security risk. Port scanning helps identify exposed services so they can be reviewed and secured.

## Requirements

- Python 3.8+

## Usage

Run from the project folder:

```bash
python port_scanner.py <target_ip>
```

Example:

```bash
python port_scanner.py 192.168.1.1
```

Optional arguments:

- `--ports`: custom ports and ranges (example: `--ports 21,22,80,443` or `--ports 1-1024`)
- `--workers`: thread count for faster scanning (default: `100`)
- `--timeout`: timeout per connection in seconds (default: `1.0`)

Example with custom options:

```bash
python port_scanner.py 192.168.1.1 --ports 21,22,80,443 --workers 200 --timeout 0.7
```

## Output Example

```text
====================================================================
Simple Port Scanner Report
====================================================================
Target IP     : 192.168.1.1
Ports scanned : 4
Elapsed time  : 0.18 sec
--------------------------------------------------------------------
PORT      STATE     SERVICE
--------------------------------------------------------------------
22        OPEN      ssh
80        OPEN      http
443       OPEN      https
====================================================================
```

## Educational Note

Use this scanner only on systems you own or have permission to test.

## 👤 Author

Developed by **Mohamed Moncef Amor**

## 📜 License

All rights reserved © Mohamed Moncef Amor
