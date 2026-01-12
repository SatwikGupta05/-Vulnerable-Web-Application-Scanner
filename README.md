# 🛡️ SOC Security Scanner

**Enterprise-Grade Web Vulnerability Assessment Tool**

A GUI-based web vulnerability scanner with full OWASP Top 10 coverage, real-time progress tracking, CVSS-inspired scoring, and professional HTML reports.

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![OWASP](https://img.shields.io/badge/OWASP-Top%2010-red.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

---

## 🎯 Problem Statement

Web applications are primary targets for cyberattacks. According to OWASP, over 90% of web applications contain security vulnerabilities. Manual security testing is:
- **Time-consuming** - Hours to test a single application
- **Error-prone** - Human testers miss vulnerabilities
- **Expensive** - Professional penetration testing costs thousands

**Solution:** Automated vulnerability scanners provide fast, consistent, and comprehensive security assessments that help developers and security teams identify weaknesses before attackers do.

---

## ✨ Features

- 🔌 **17 Vulnerability Modules** - SQL Injection, XSS, SSRF, Command Injection, and more
- 🎯 **OWASP 2021 + 2025** - Complete Top 10 coverage for both versions
- 📊 **CVSS Scoring** - Professional severity assessment (0.0-10.0)
- 🖥️ **Real-Time GUI** - Visual progress tracking 0-100%
- 📋 **HTML Reports** - Executive summary with step-by-step remediation
- 🔒 **Safe Testing** - Non-destructive payloads for ethical scanning

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        SOC Security Scanner                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────┐    ┌──────────────┐    ┌─────────────────────┐   │
│  │  INPUT   │───▶│    CRAWLER   │───▶│   SCANNER ENGINE    │   │
│  │  (URL)   │    │  (Forms,URLs)│    │   (Orchestrator)    │   │
│  └──────────┘    └──────────────┘    └──────────┬──────────┘   │
│                                                  │               │
│                    ┌─────────────────────────────┼───────────┐  │
│                    │         PLUGIN MODULES      ▼           │  │
│                    │  ┌─────────┐ ┌─────────┐ ┌─────────┐   │  │
│                    │  │   SQL   │ │   XSS   │ │  SSRF   │   │  │
│                    │  │Injection│ │ Scanner │ │ Scanner │   │  │
│                    │  └─────────┘ └─────────┘ └─────────┘   │  │
│                    │  ┌─────────┐ ┌─────────┐ ┌─────────┐   │  │
│                    │  │  SSL/   │ │Security │ │  Port   │   │  │
│                    │  │  TLS    │ │ Headers │ │ Scanner │   │  │
│                    │  └─────────┘ └─────────┘ └─────────┘   │  │
│                    │         ... 17 modules total ...        │  │
│                    └─────────────────────────────────────────┘  │
│                                       │                          │
│                    ┌──────────────────▼──────────────────┐      │
│                    │         SEVERITY ENGINE             │      │
│                    │    (CVSS Scoring & Classification)  │      │
│                    └──────────────────┬──────────────────┘      │
│                                       │                          │
│                    ┌──────────────────▼──────────────────┐      │
│                    │         REPORT GENERATOR            │      │
│                    │      (HTML Reports + Dashboard)     │      │
│                    └─────────────────────────────────────┘      │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## ✅ Scope - What It Detects

| Category | Vulnerabilities |
|----------|-----------------|
| **Injection** | SQL Injection, XSS, Command Injection |
| **Access Control** | Directory Traversal, IDOR, SSRF |
| **Cryptography** | Weak SSL/TLS, Expired Certificates |
| **Misconfiguration** | Missing Headers, Open Ports, Directory Listing |
| **Components** | Outdated Libraries, Version Disclosure |
| **Authentication** | Insecure Login, Session Issues |
| **Integrity** | Missing CSRF Tokens |
| **Supply Chain** | Vulnerable Dependencies, Missing SRI |

---

## ⚠️ Limitations - What It Does NOT Detect

| Limitation | Reason |
|------------|--------|
| **Business Logic Flaws** | Requires understanding of application context |
| **Authenticated Scanning** | Currently supports unauthenticated testing only |
| **API-Specific Vulnerabilities** | Designed for web pages, not REST/GraphQL APIs |
| **Zero-Day Vulnerabilities** | Uses known patterns and signatures |
| **Client-Side Only Issues** | Limited JavaScript execution analysis |
| **Rate-Limited Endpoints** | May not detect all issues on protected endpoints |
| **WAF-Protected Sites** | Web Application Firewalls may block test payloads |

**Important:** This tool is meant to assist security testing, not replace professional penetration testing.

---

## 🚀 Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run the scanner
python main.py
```

### Usage
1. Enter target URL (e.g., `example.com`)
2. Click **Start Scan**
3. Monitor progress in **Scan Progress** tab
4. Review findings in **Findings** tab
5. Generate HTML report via **Generate Report** button

---

## 🔍 Vulnerability Modules

### OWASP 2021
| Module | Category | Description |
|--------|----------|-------------|
| SQL Injection | A03 | Error-based SQL injection detection |
| XSS Scanner | A03 | Reflected & stored cross-site scripting |
| Command Injection | A03 | OS command injection |
| SSL/TLS Checker | A02 | Certificate & cipher validation |
| Security Headers | A05 | CSP, HSTS, X-Frame-Options |
| Port Scanner | A05 | Open port detection |
| Directory Traversal | A01 | Path traversal vulnerabilities |
| IDOR Scanner | A01 | Insecure Direct Object References |
| CSRF Detector | A08 | Missing anti-CSRF tokens |
| SSRF Scanner | A10 | Server-Side Request Forgery |
| Error Disclosure | A09 | Stack trace exposure |
| Outdated Components | A06 | Version fingerprinting |
| Auth Scanner | A07 | Authentication weaknesses |

### OWASP 2025 (NEW)
| Module | Category | Description |
|--------|----------|-------------|
| Supply Chain Scanner | A03:2025 | Vulnerable libraries, missing SRI |
| Insecure Design | A06:2025 | Missing rate limiting, CAPTCHA |
| Exceptional Conditions | A10:2025 | Fail-open scenarios |

---

## 📁 Project Structure

```
├── main.py              # Entry point
├── requirements.txt     # Dependencies
├── core/                # Engine, crawler, models, severity scoring
├── plugins/             # 17 vulnerability scanner modules
├── gui/                 # Tkinter interface (progress, results, dashboard)
├── reports/             # HTML report generator
└── utils/               # HTTP client, validators
```

---

## 🛠️ Tech Stack

| Component | Technology |
|-----------|------------|
| GUI | Tkinter |
| HTTP | requests, urllib3 |
| Parsing | BeautifulSoup4, lxml |
| SSL | ssl, cryptography |
| Reports | Jinja2 |

---

## ⚠️ Disclaimer

**For authorized testing only.** Only scan systems you have explicit permission to test. The developers are not responsible for misuse.

**Safe testing targets:** OWASP WebGoat, DVWA, your own test servers.

---

## 📄 License

MIT License

---

**Built with ❤️ for the security community**