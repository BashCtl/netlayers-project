# Netlayers

Netlayers is a small Python networking project developed for Linux. It implements
Ethernet, ARP, IPv4, ICMP, TCP, and UDP packet helpers, along with command-line
tools for packet capture, ping, and traceroute.

The packet capture and probing tools use Linux raw packet sockets (`AF_PACKET`).
They need root privileges or the appropriate raw-socket capability.

## Requirements

- Linux
- Python 3.10 or newer
- Root access or `CAP_NET_RAW` when running the network tools

## Install

From the project directory, create a virtual environment and install the listed
dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## Tools

Run the tools as Python modules from the project directory.

### Ping

```bash
sudo .venv/bin/python -m tools.ping 8.8.8.8
sudo .venv/bin/python -m tools.ping 8.8.8.8 --count 5 --timeout 1.5
```

`--count` sets the number of echo requests (default: `4`). `--timeout` sets the
reply timeout in seconds (default: `2.0`).

### Traceroute

```bash
sudo .venv/bin/python -m tools.traceroute 8.8.8.8
sudo .venv/bin/python -m tools.traceroute 8.8.8.8 --max-hops 20 --timeout 1
```

`--max-hops` sets the hop limit (default: `30`, supported range: `1`–`255`).
`--timeout` sets the wait time per probe in seconds (default: `1.0`). Traceroute
sends three probes per hop.

### Packet sniffer

Choose a Linux network interface, for example with `ip link`, and pass its name
to the sniffer:

```bash
ip link
sudo .venv/bin/python -m tools.sniffer --interface eth0
sudo .venv/bin/python -m tools.sniffer -i eth0 --count 10 --display raw
sudo .venv/bin/python -m tools.sniffer -i eth0 --pcap-file captures/traffic.pcap
sudo .venv/bin/python -m tools.sniffer -i eth0 --text-file captures/traffic.txt
```

The default display is parsed packet details. Use `--display raw` to print a
hex dump. `--count` defaults to `0`, which captures until interrupted with
Ctrl+C. The text and PCAP writers append to their output files.

## Library modules

The `netlayers` package contains packet builders, parsers, checksums, and
formatting/dissection helpers. The dissector currently recognizes Ethernet,
ARP, IPv4, ICMP, TCP, and UDP packets.

## Tests

Install the requirements, then run the test suite from the project directory:

```bash
.venv/bin/python -m pytest
```

Most tests exercise packet construction and parsing and do not require raw
socket privileges. Running the command-line network tools does require them.
