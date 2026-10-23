# netwatch

netwatch is a Linux command-line project for exploring local network traffic in C. It can discover IPv4 devices with ARP, capture packets on a network interface, and show hostnames found in TLS and QUIC connection handshakes. It can also use ARP spoofing to route selected devices' traffic through the computer running netwatch. It does not change the router's configuration.

Use spoofing only on networks and devices you own or are authorized to inspect. It can briefly disrupt connectivity.

## Build

You need Linux, `gcc`, `make`, and the OpenSSL development headers and library (`libcrypto`). Raw packet sockets and changes to IPv4 forwarding require root privileges.

The interface name is currently set to `wlp0s20f3` in `IFNAME` near the top of `src/main.c`. Check yours with `ip -4 addr show`, change `IFNAME` if needed, then build:

```sh
make
```

## Usage

```sh
sudo ./netwatch
sudo ./netwatch --scan
sudo ./netwatch --spoof 192.168.1.134 192.168.1.1
sudo ./netwatch --spoof 192.168.1.134 192.168.1.1 192.168.1.18
sudo ./netwatch --all
```

Replace the example target and gateway IPs with addresses from your own network.

| Mode | Behavior |
| --- | --- |
| No flag | Capture packets visible to this computer. |
| `--scan` | Send ARP requests across the local IPv4 subnet, print devices that reply, then exit. |
| `--spoof TARGET GATEWAY [MORE_TARGETS...]` | Route traffic between the named targets and gateway through this computer while capturing it. The gateway is always the second address. |
| `--all` or `-all` | Scan once, print all discovered IPs and the selected targets, then spoof up to 64 discovered clients. Your computer and the gateway are excluded. |

The spoofing modes cannot be combined with `--scan`, and only one netwatch spoofing process can run at a time. Press **Ctrl+C** to stop. The program then sends the real ARP mappings to the targets and gateway and restores this computer's original IPv4 forwarding setting if it changed it.

During capture, netwatch prints a table roughly every ten seconds with `COUNT`, `WEBSITE`, `VISITOR IP`, and `LAST SEEN`. The visitor IP is the source IP of the packet containing the hostname. Rows are grouped by hostname and source IP; counts are hostname observations, including background app traffic, rather than confirmed page visits. The heading number is the number of distinct rows, and counts accumulate until the program exits.

Packet details and short hex/ASCII payload dumps go to `netwatch.log` in the current directory. Each capture run **overwrites** that file. It may contain sensitive data from unencrypted traffic, so handle it accordingly. `--scan` only prints scan results and does not create the log.

## How it works

1. **Discovery:** ARP asks which device owns each usable IPv4 address on the local subnet. Replies supply IP and MAC address pairs. A device that does not reply during the scan will not appear.
2. **Spoofing:** For each target, netwatch tells the target that the gateway IP is at this computer's MAC address and tells the gateway that the target IP is at this computer's MAC address. Linux IPv4 forwarding passes the intercepted packets onward. The program repeats these ARP replies about every two seconds.
3. **Capture:** A Linux `AF_PACKET` raw socket receives Ethernet frames on the chosen interface. The parser reads IPv4 and TCP or UDP headers.
4. **Hostnames:** For TCP, it looks for the Server Name Indication (SNI) in a TLS ClientHello. For UDP port 443, it derives QUIC version 1 Initial keys, decrypts Initial packets, and looks for the ClientHello hostname. OpenSSL's `libcrypto` supplies the cryptographic functions.
5. **Statistics:** It records each hostname with the packet's source IPv4 address, updates its count and last-seen time, and prints the table periodically.

The main implementation is in `src/main.c`. `tests/test_hd.c` and `tests/test_keys.c` are small standalone QUIC experiments; the Makefile builds only `netwatch`.

## Limits

- A scan finds responding devices on the local IPv4 subnet, not necessarily every device connected to Wi-Fi. `--all` uses only the results of its startup scan; it does not add devices later.
- The hostname table is incomplete by design. It does not reveal URLs or encrypted page contents. TLS handshakes split across TCP packets, unsupported QUIC versions, encrypted ClientHello, VPNs, and IPv6 traffic may not produce a hostname. QUIC ClientHello assembly tracks one connection at a time.
- A crash or forced termination can skip ARP and forwarding cleanup. Normal cleanup runs when you press Ctrl+C.
