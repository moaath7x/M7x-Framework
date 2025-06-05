# M7x-Framework

A Powerful Python-based Penetration Testing Framework I built when I was 16-Year-Old Developer, Includes tools for Information Gathering, Sniffing, Spoofing, Password Attacks, Web Scanning, Exploitation, and more — all in one CLI Interface.


# Features

1. Information Gathering

-- IP geolocation lookup (using GeoLite2)

-- DNS record analysis

-- Username reconnaissance across +70 social networks

-- Instagram public data extraction (bio, ID, status, profile picture)

-- Wordlist (password list) generator

2. Sniffing & Spoofing

-- DNS spoofing (MITM)

-- HTTP request sniffing

-- ARP spoofing

3. Password Attacks

-- Hash type detection (MD5, SHA1, SHA256, etc.)

-- Hash encryption (MD5, SHA, SHA3)

-- Brute-force hash cracking using wordlists

-- Python script encryption

4. Network Scanner

-- ARP network scanner (local devices)

-- Port scanner (common services)

-- Live packet analyzer with service & location info

5. Web Scanning

-- SQL dork search (Google-based)

-- XSS vulnerability scanner

-- DDoS attack (UDP flood)

-- Admin page & hidden path finder

-- Subdomain discovery

6. Exploitation Tools

-- Nmap-based vulnerability scanning

-- Metasploit payload generation (Android, Windows, Linux, PHP, Mac)

-- Payload merger (bind malicious code into files)

-- Keylogger builder (WIP)

-- Remote Access Trojan (M7x-RAT) with file download/upload, shell, and screenshot

7. Other Tools

-- Proxy scraper (HTTP, HTTPS, SOCKS4, SOCKS5)

-- Free hosting & FTP account generator

-- Link shortener (TinyURL)

-- Visa card number generator (demo only)

8. External Links

-- GitHub, Telegram, YouTube, Instagram, and more

# Technologies & Libraries Used

-- Language: Python 3, Bash

# Libraries & Modules:

-- scapy (packet sniffing, ARP spoofing)

-- requests (web requests)

-- geoip (geolite2) (IP location)

-- pyshorteners (link shortening)

-- socket, subprocess, os, sys, re

-- dns.resolver, hashlib, pyautogui

-- py_compile, secrets, webbrowser

-- BeautifulSoup (HTML parsing)

-- googlesearch

# Legal Disclaimer

-- This tool is intended strictly for educational purposes and authorized penetration testing.
The author is not responsible for any misuse or illegal activity carried out with this tool.

# Structure

bash
Copy code
M7x-Framework/
├── M7x-Framework.py
├── Wordlists/
│   ├── Password-list.txt
│   ├── Admin-page-list.txt
│   ├── Web-tracks-list.txt
│   └── Sub-domain-list.txt
├── Malware/
│   └── Generated payloads, keyloggers
└── Scripts/
    └── Card.php (Visa generator)
