# 🔐 Cybersecurity Journey

My path from CSE student at **NIT Srinagar** to cybersecurity engineer. This repo holds my notes, lab logs, CTF write-ups and small security tools, updated as I learn.

> Everything here is for learning. I only practise on my own machines and on platforms built for it (TryHackMe, OverTheWire, PortSwigger Academy, picoCTF).

## 📂 What's inside

| Folder | What goes there |
|--------|-----------------|
| [`notes/`](notes) | My study notes, one file per topic |
| [`labs/`](labs) | A log of every lab and room I complete |
| [`ctf-writeups/`](ctf-writeups) | How I solved CTF challenges, step by step |
| [`tools/`](tools) | Small security tools I write in Python |

## 🗺️ Roadmap

### Phase 1: Foundations
- [ ] Networking basics: OSI and TCP/IP models, IP addresses, ports, DNS, HTTP → [notes](notes/01-networking-basics.md)
- [ ] Linux command line and permissions → [notes](notes/02-linux-basics.md)
- [ ] TryHackMe: **Pre Security** path
- [ ] OverTheWire: **Bandit** levels 0–15

### Phase 2: Web security
- [ ] OWASP Top 10 → [notes](notes/03-owasp-top-10.md)
- [ ] PortSwigger Web Security Academy: SQL injection labs
- [ ] PortSwigger Web Security Academy: Cross-site scripting (XSS) labs
- [ ] Learn Burp Suite (Community Edition)

### Phase 3: Practice
- [ ] Solve 10 picoCTF challenges and write them up
- [ ] TryHackMe: **Jr Penetration Tester** path
- [ ] Take part in a live CTF competition

### Phase 4: Go deeper
- [ ] Cryptography basics: hashing, symmetric and public-key encryption
- [ ] Network security: Wireshark and Nmap on my own lab network
- [ ] Pick a focus area: web pentesting, network security, or blue team (defence)

## 🛠️ Tools

| Tool | What it does |
|------|--------------|
| [`password_checker.py`](tools/password_checker.py) | Scores a password's strength and explains how to improve it |
| [`header_checker.py`](tools/header_checker.py) | Grades a website's security headers (HSTS, CSP, clickjacking, cookies, version leaks) from A+ to F |
| [**log-analyzer**](https://github.com/urstrulyrammukesh/log-analyzer) (own repo) | Finds attacks in web and SSH logs: brute force, scanners, SQLi, XSS, Log4Shell, mapped to MITRE ATT&CK |

## 📚 Resources I use

- [TryHackMe](https://tryhackme.com): guided, beginner-friendly rooms
- [OverTheWire: Bandit](https://overthewire.org/wargames/bandit/): learn Linux by playing
- [PortSwigger Web Security Academy](https://portswigger.net/web-security): free web security labs
- [picoCTF](https://picoctf.org): CTF practice for students
- [OWASP Top 10](https://owasp.org/www-project-top-ten/): the most critical web app risks

## 📈 Progress

| Date | What I did |
|------|------------|
| Nov 2026 | Started this repo and the roadmap |
| Nov 2026 | Security-audited my own app [Clinora](https://github.com/urstrulyrammukesh/clinora/blob/main/docs/security-audit.md): 9 findings fixed, STRIDE [threat model](https://github.com/urstrulyrammukesh/clinora/blob/main/docs/threat-model.md) |
| Nov 2026 | Built [log-analyzer](https://github.com/urstrulyrammukesh/log-analyzer) (blue team) and `header_checker.py` |
