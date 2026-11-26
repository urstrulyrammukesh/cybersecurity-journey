# 01 · Networking Basics

Security starts with knowing how data moves. If you don't know what normal traffic looks like, you can't spot an attack.

## The TCP/IP model (what the internet actually uses)

| Layer | Job | Examples |
|-------|-----|----------|
| Application | What the user's program speaks | HTTP, HTTPS, DNS, SSH, FTP |
| Transport | Delivers data between programs, using ports | TCP, UDP |
| Internet | Routes packets between networks | IP, ICMP |
| Link | Moves frames on the local network | Ethernet, Wi-Fi, ARP |

The **OSI model** splits the same idea into 7 layers (Physical, Data Link, Network, Transport, Session, Presentation, Application). It's mostly used for talking about where a problem sits ("that's a layer 7 attack").

## IP addresses

- **IPv4:** four numbers 0–255, like `192.168.1.10`
- **Private ranges** (not reachable from the internet): `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- `127.0.0.1` is **localhost**, your own machine
- **CIDR:** `/24` means the first 24 bits are the network, so `192.168.1.0/24` covers `192.168.1.0`–`192.168.1.255`

## TCP vs UDP

| | TCP | UDP |
|---|-----|-----|
| Connection | Yes, the 3-way handshake (SYN → SYN-ACK → ACK) | No |
| Reliable | Yes, resends lost data | No |
| Speed | Slower | Faster |
| Used for | Web, email, SSH | DNS, video calls, games |

## Ports worth knowing

| Port | Service |
|------|---------|
| 21 | FTP |
| 22 | SSH |
| 23 | Telnet (unencrypted, avoid) |
| 25 | SMTP (email) |
| 53 | DNS |
| 80 | HTTP |
| 443 | HTTPS |
| 3306 | MySQL |
| 3389 | RDP (Windows Remote Desktop) |

An open port means a program is listening. Every open port is something an attacker could try to talk to, so close what you don't need.

## DNS

DNS turns names into IP addresses. `google.com` → `142.250.x.x`.
Common record types: **A** (IPv4), **AAAA** (IPv6), **CNAME** (alias), **MX** (mail server), **TXT** (text, used for verification and email security).

## HTTP

- **Methods:** GET (read), POST (send), PUT (replace), DELETE (remove)
- **Status codes:** 200 OK, 301/302 redirect, 401 not logged in, 403 forbidden, 404 not found, 500 server error
- **HTTPS** = HTTP inside TLS encryption. Without it, anyone on the same network can read the traffic.

## Try it yourself (on your own machine)

```bash
ping -c 4 google.com          # is the host reachable?
nslookup google.com           # DNS lookup
curl -I https://example.com   # see HTTP response headers
netstat -an | grep LISTEN     # which ports are open on MY machine
```

## ✅ Self-check
- [ ] I can explain the TCP 3-way handshake
- [ ] I know why `192.168.x.x` can't be reached from the internet
- [ ] I can name the port for SSH, DNS and HTTPS without looking
