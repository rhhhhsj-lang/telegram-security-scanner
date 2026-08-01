# 🔐 Security Scanner Bot PRO

An advanced Telegram bot for passive security scanning with support for non-destructive proof-of-concept (PoC) vulnerability testing.

> ⚠️ **Legal Disclaimer:** This project is for educational and authorized security testing purposes only. You must own the target website or have explicit written permission to test it.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 **Passive Scanning** | Check security headers, SSL certificates, open ports |
| 📁 **Sensitive File Detection** | Find exposed files like `.env`, `wp-config.php`, `.git/config` |
| 🔧 **Technology Fingerprinting** | Detect frameworks (WordPress, Laravel, Django, React...) |
| 🚨 **Non-Destructive PoC** | Test for XSS, SQL Injection, Directory Traversal (read-only) |
| 📄 **PDF Reports** | Generate professional PDF reports |
| ⏰ **Scheduled Scans** | Schedule scans (hourly / daily / weekly) |
| 🔑 **License System** | License key support for PRO features |

---

## 🛠️ Requirements

- Python 3.8+
- pip

### Dependencies

```bash
pip install pyTelegramBotAPI requests reportlab cryptography
