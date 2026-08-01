#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
🔐 Security Scanner Bot - PRO Version (with Vulnerability Proof-of-Concept)

⚠️ EXTREMELY IMPORTANT DISCLAIMER:
This bot performs ONLY PASSIVE, READ-ONLY scanning by default.
The vulnerability exploitation feature is provided for EDUCATIONAL and AUTHORIZED testing ONLY.
You MUST have explicit WRITTEN PERMISSION to test the target.
No data is modified or deleted. Only non-destructive proofs are shown.
The developer assumes NO LIABILITY for any misuse.
"""

import os
import sys
import time
import json
import sqlite3
import logging
import socket
import ipaddress
import hashlib
import re
import threading
import urllib.parse
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Tuple
from urllib.parse import urlparse, urljoin

import telebot
from telebot import types
import requests
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from cryptography.fernet import Fernet

# ─────────────────────────────────────────────
# ⚠️ LEGAL DISCLAIMER & WARNING
# ─────────────────────────────────────────────

LEGAL_DISCLAIMER = """
╔══════════════════════════════════════════════════════════════╗
║  ⚠️  EXTREME LEGAL WARNING - READ CAREFULLY                ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  This software is provided for AUTHORIZED security         ║
║  testing and educational purposes ONLY.                    ║
║                                                              ║
║  ✅ DEFAULT MODE: PASSIVE, READ-ONLY scanning.             ║
║  ⚠️  EXPLOIT MODE: NON-DESTRUCTIVE proof-of-concept only. ║
║                                                              ║
║  The exploitation feature performs:                         ║
║  • Simple parameter injection (GET/POST)                  ║
║  • File path checks (read-only, no modification)          ║
║  • No data is deleted or modified                         ║
║  • No malicious payloads are executed                    ║
║                                                              ║
║  ⚠️  YOU MUST:                                              ║
║  • Own the target website                                   ║
║  • OR have EXPLICIT WRITTEN PERMISSION                     ║
║  • Use this feature ONLY for authorized testing            ║
║                                                              ║
║  ⚠️  Unauthorized testing is ILLEGAL and may result in:    ║
║  • Criminal charges                                         ║
║  • Civil lawsuits                                           ║
║  • Permanent account ban                                    ║
║                                                              ║
║  THE DEVELOPER ASSUMES NO LIABILITY FOR ANY MISUSE.        ║
║  YOU ARE SOLELY RESPONSIBLE FOR YOUR ACTIONS.              ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
"""

EXPLOIT_WARNING = """
╔══════════════════════════════════════════════════════════════╗
║  ⚠️  EXPLOIT MODE WARNING                                   ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  You are about to use the EXPLOIT feature.                 ║
║                                                              ║
║  This will perform NON-DESTRUCTIVE proof-of-concept        ║
║  tests to demonstrate vulnerabilities.                     ║
║                                                              ║
║  ✅ No data will be modified or deleted.                   ║
║  ✅ Only READ-ONLY checks will be performed.              ║
║  ✅ No malicious payloads will be sent.                   ║
║                                                              ║
║  ⚠️  You must have WRITTEN PERMISSION to test.             ║
║  ⚠️  Unauthorized testing is ILLEGAL.                     ║
║                                                              ║
║  Type /confirm_exploit to proceed.                        ║
║  Type /cancel to abort.                                   ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
"""

def show_legal_disclaimer():
    print(LEGAL_DISCLAIMER)
    print("\n⚠️ Do you agree to these terms? (yes/no): ", end="")
    response = input().strip().lower()
    if response != 'yes':
        print("❌ You must agree to the terms to use this software.")
        sys.exit(1)
    print("✅ Terms accepted. Starting bot...\n")

if '--skip-disclaimer' not in sys.argv:
    show_legal_disclaimer()

# ─────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
if not BOT_TOKEN:
    raise ValueError("❌ TELEGRAM_BOT_TOKEN is not set.")

bot = telebot.TeleBot(BOT_TOKEN)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

DB_FILE = "scanner_pro.db"
LICENSE_KEY = os.getenv("LICENSE_KEY", "PRO-2024-DEMO-KEY")

# ─────────────────────────────────────────────
# Database Setup
# ─────────────────────────────────────────────

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY,
            license_key TEXT,
            expires_at INTEGER,
            scans_count INTEGER DEFAULT 0,
            daily_limit INTEGER DEFAULT 10
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            target_url TEXT,
            scan_date INTEGER,
            result TEXT,
            FOREIGN KEY (user_id) REFERENCES users(user_id)
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS scheduled_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            target_url TEXT,
            frequency TEXT,
            next_run INTEGER,
            active INTEGER DEFAULT 1
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS terms_acceptance (
            user_id INTEGER PRIMARY KEY,
            accepted_at INTEGER
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS exploit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            target_url TEXT,
            exploit_type TEXT,
            timestamp INTEGER,
            details TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# ─────────────────────────────────────────────
# License Verification
# ─────────────────────────────────────────────

def verify_license(user_id: int, license_key: str) -> Tuple[bool, Optional[int]]:
    if license_key == LICENSE_KEY:
        expires_at = int(time.time()) + 365 * 24 * 3600
        return True, expires_at
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT expires_at FROM users WHERE user_id = ? AND license_key = ?", (user_id, license_key))
    row = c.fetchone()
    conn.close()
    if row and row[0] > int(time.time()):
        return True, row[0]
    return False, None

def get_user_license(user_id: int) -> Optional[Dict]:
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT license_key, expires_at FROM users WHERE user_id = ?", (user_id,))
    row = c.fetchone()
    conn.close()
    if row:
        return {"license_key": row[0], "expires_at": row[1]}
    return None

def save_user_license(user_id: int, license_key: str, expires_at: int):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute(
        "INSERT OR REPLACE INTO users (user_id, license_key, expires_at) VALUES (?, ?, ?)",
        (user_id, license_key, expires_at)
    )
    conn.commit()
    conn.close()

def record_terms_acceptance(user_id: int):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO terms_acceptance (user_id, accepted_at) VALUES (?, ?)", (user_id, int(time.time())))
    conn.commit()
    conn.close()

def has_accepted_terms(user_id: int) -> bool:
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT 1 FROM terms_acceptance WHERE user_id = ?", (user_id,))
    row = c.fetchone()
    conn.close()
    return row is not None

def log_exploit(user_id: int, target_url: str, exploit_type: str, details: str):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute(
        "INSERT INTO exploit_logs (user_id, target_url, exploit_type, timestamp, details) VALUES (?, ?, ?, ?, ?)",
        (user_id, target_url, exploit_type, int(time.time()), details)
    )
    conn.commit()
    conn.close()

# ─────────────────────────────────────────────
# SSRF Protection
# ─────────────────────────────────────────────

BLOCKED_HOSTS = [
    'localhost', '127.0.0.1', '0.0.0.0', '::1',
    '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16',
    '169.254.169.254', 'fc00::/7', 'fe80::/10'
]

ALLOWED_EXCEPTIONS = [
    'example.com',
]

def is_internal_ip(hostname: str) -> bool:
    if hostname.lower() in [ex.lower() for ex in ALLOWED_EXCEPTIONS]:
        return False
    try:
        ip = socket.gethostbyname(hostname)
        addr = ipaddress.ip_address(ip)
        for blocked in BLOCKED_HOSTS:
            if '/' in blocked:
                if addr in ipaddress.ip_network(blocked, strict=False):
                    return True
            elif str(addr) == blocked or hostname.lower() == blocked:
                return True
        return False
    except Exception:
        return True

def validate_url(target: str) -> Tuple[Optional[str], Optional[str]]:
    target = target.strip()
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    parsed = urlparse(target)
    if not parsed.netloc:
        return None, "⚠️ Invalid URL. Example: <code>example.com</code>"
    if is_internal_ip(parsed.hostname):
        return None, "🚫 <b>Blocked:</b> Internal or local addresses are not allowed."
    return target, None

def escape_html(text: str) -> str:
    if not isinstance(text, str):
        text = str(text)
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

# ─────────────────────────────────────────────
# Security Analysis Functions (PASSIVE ONLY)
# ─────────────────────────────────────────────

def analyze_security_headers(headers: Dict[str, str]) -> Dict[str, Any]:
    result = {
        "checks": [],
        "score": 0,
        "max_score": 6,
        "missing": []
    }
    score = 0
    checks = []

    if 'Strict-Transport-Security' in headers:
        checks.append({"name": "HSTS", "passed": True, "value": headers.get('Strict-Transport-Security')})
        score += 1
    else:
        checks.append({"name": "HSTS", "passed": False, "value": None})
        result["missing"].append("Enable HSTS")

    csp = headers.get('Content-Security-Policy', '')
    has_frame = 'X-Frame-Options' in headers or 'frame-ancestors' in csp
    if has_frame:
        checks.append({"name": "Clickjacking Protection", "passed": True, "value": headers.get('X-Frame-Options', 'CSP')})
        score += 1
    else:
        checks.append({"name": "Clickjacking Protection", "passed": False, "value": None})
        result["missing"].append("Enable Clickjacking protection (X-Frame-Options or CSP frame-ancestors)")

    if 'Content-Security-Policy' in headers:
        checks.append({"name": "CSP", "passed": True, "value": headers.get('Content-Security-Policy')[:50] + "..."})
        score += 1
    else:
        checks.append({"name": "CSP", "passed": False, "value": None})
        result["missing"].append("Enable CSP")

    if 'X-Content-Type-Options' in headers:
        checks.append({"name": "X-Content-Type-Options", "passed": True, "value": headers.get('X-Content-Type-Options')})
        score += 1
    else:
        checks.append({"name": "X-Content-Type-Options", "passed": False, "value": None})
        result["missing"].append("Enable X-Content-Type-Options: nosniff")

    if 'Referrer-Policy' in headers:
        checks.append({"name": "Referrer-Policy", "passed": True, "value": headers.get('Referrer-Policy')})
        score += 1
    else:
        checks.append({"name": "Referrer-Policy", "passed": False, "value": None})
        result["missing"].append("Enable Referrer-Policy")

    server = headers.get('Server', 'Unknown')
    checks.append({"name": "Server", "passed": True, "value": server})

    result["checks"] = checks
    result["score"] = score
    return result

def analyze_ssl_certificate(hostname: str) -> Dict[str, Any]:
    result = {"valid": False, "details": {}}
    try:
        import ssl
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    expiry = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_left = (expiry - datetime.now()).days
                    result["valid"] = days_left > 0
                    result["details"] = {
                        "subject": dict(x[0] for x in cert['subject']),
                        "issuer": dict(x[0] for x in cert['issuer']),
                        "expiry_days": days_left,
                        "tls_version": ssock.version(),
                        "cipher": ssock.cipher()
                    }
    except Exception as e:
        result["error"] = str(e)
    return result

def scan_open_ports(hostname: str) -> List[int]:
    common_ports = [21, 22, 25, 80, 443, 3306, 5432, 8080, 8443]
    open_ports = []
    for port in common_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((hostname, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except:
            pass
    return open_ports

def detect_sensitive_files(base_url: str) -> List[str]:
    sensitive_paths = [
        '/robots.txt', '/.env', '/wp-config.php', '/config.php',
        '/.git/config', '/.htaccess', '/web.config', '/phpinfo.php',
        '/info.php', '/admin/', '/backup/', '/sql/', '/debug/'
    ]
    found = []
    for path in sensitive_paths:
        try:
            test_url = base_url.rstrip('/') + path
            resp = requests.get(test_url, timeout=5, allow_redirects=False)
            if resp.status_code == 200:
                found.append(path)
        except:
            pass
    return found

def detect_technologies(url: str) -> List[str]:
    tech = []
    try:
        resp = requests.get(url, timeout=10, headers={'User-Agent': 'Mozilla/5.0'})
        headers = resp.headers
        content = resp.text[:10000].lower()

        if 'server' in headers:
            tech.append(f"Server: {headers['server']}")
        if 'x-powered-by' in headers:
            tech.append(f"X-Powered-By: {headers['x-powered-by']}")

        patterns = {
            'WordPress': ['wordpress', 'wp-content', 'wp-includes'],
            'Laravel': ['laravel', 'csrf-token'],
            'Django': ['django', 'csrfmiddlewaretoken'],
            'Angular': ['ng-app', 'angular'],
            'React': ['react', 'react-dom'],
            'Vue.js': ['vue.js', 'v-bind'],
            'jQuery': ['jquery', '$('],
            'Bootstrap': ['bootstrap', 'container-fluid'],
        }
        
        for name, keywords in patterns.items():
            if any(k in content for k in keywords):
                tech.append(name)
                
    except:
        pass
    return tech

def check_robots_txt(base_url: str) -> Tuple[bool, Optional[str]]:
    try:
        url = base_url.rstrip('/') + '/robots.txt'
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            return True, resp.text[:500]
        return False, None
    except:
        return False, None

# ─────────────────────────────────────────────
# 🚨 EXPLOIT / PROOF-OF-CONCEPT FUNCTIONS
# ─────────────────────────────────────────────

def detect_vulnerabilities(scan_result: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    تحليل نتائج الفحص لاكتشاف ثغرات محتملة.
    هذه دوال غير مدمرة، فقط تقدم دليلاً على وجود الثغرة.
    """
    vulnerabilities = []
    
    # 1. ملفات حساسة مكشوفة
    sensitive_files = scan_result.get('sensitive_files', [])
    if sensitive_files:
        for file_path in sensitive_files:
            vulnerabilities.append({
                "type": "sensitive_file_exposure",
                "path": file_path,
                "severity": "high",
                "description": f"Sensitive file exposed: {file_path}",
                "proof": f"File is accessible at {scan_result.get('target_url', '')}{file_path}"
            })
    
    # 2. نقاط ضعف في الهيدرز (مثل عدم وجود CSP قد يؤدي إلى XSS)
    missing_headers = scan_result.get('missing_headers', [])
    if 'Enable CSP' in missing_headers:
        vulnerabilities.append({
            "type": "missing_csp",
            "severity": "medium",
            "description": "CSP header missing - possible XSS risk",
            "proof": "Content-Security-Policy header not found in response"
        })
    
    # 3. SSL ضعيف
    ssl_info = scan_result.get('ssl', {})
    if ssl_info.get('valid') and ssl_info.get('details', {}).get('expiry_days', 30) < 30:
        vulnerabilities.append({
            "type": "ssl_expiring_soon",
            "severity": "low",
            "description": f"SSL certificate expires in {ssl_info['details']['expiry_days']} days",
            "proof": f"Certificate expires on {datetime.now() + timedelta(days=ssl_info['details']['expiry_days'])}"
        })
    
    # 4. منافذ مفتوحة حساسة
    open_ports = scan_result.get('open_ports', [])
    sensitive_ports = [21, 22, 25, 3306, 5432]
    for port in open_ports:
        if port in sensitive_ports:
            vulnerabilities.append({
                "type": "sensitive_open_port",
                "severity": "medium",
                "description": f"Sensitive port {port} is open",
                "proof": f"Port {port} is accessible from the internet"
            })
    
    return vulnerabilities

def demonstrate_xss_vulnerability(base_url: str) -> Dict[str, Any]:
    """
    عرض دليل على ثغرة XSS عن طريق حقن نص تجريبي غير ضار.
    NO DATA IS MODIFIED. ONLY READS RESPONSE.
    """
    result = {"success": False, "proof": "", "details": ""}
    try:
        # اختبار حقن بسيط باستخدام معلمة GET
        test_payload = "<script>alert('XSS Test')</script>"
        parsed = urlparse(base_url)
        if parsed.query:
            test_url = base_url + "&xss_test=" + urllib.parse.quote(test_payload)
        else:
            test_url = base_url + "?xss_test=" + urllib.parse.quote(test_payload)
        
        resp = requests.get(test_url, timeout=10, headers={'User-Agent': 'SecurityBot-PoC'})
        
        # التحقق مما إذا كان النص المحقون يظهر في الاستجابة (دليل بسيط)
        if test_payload in resp.text:
            result["success"] = True
            result["proof"] = "Payload reflected in response (XSS possible)"
            result["details"] = f"Tested URL: {test_url}\nPayload was found in response."
        else:
            # قد لا تكون معلمة GET قابلة للحقن، نحاول باستخدام POST أو غيرها (للبساطة نكتفي بـ GET)
            result["proof"] = "Payload not reflected in response (may not be vulnerable to simple XSS)"
            result["details"] = "This does not rule out other XSS vectors."
    except Exception as e:
        result["details"] = f"Error during XSS test: {e}"
    return result

def demonstrate_sql_injection_vulnerability(base_url: str) -> Dict[str, Any]:
    """
    عرض دليل على ثغرة SQL Injection (غير مدمر).
    يتم إرسال معاملات تجريبية آمنة (مثل ' OR 1=1 --) وقراءة الاستجابة.
    """
    result = {"success": False, "proof": "", "details": ""}
    try:
        # معاملات اختبار آمنة
        test_payloads = ["' OR 1=1 --", "' UNION SELECT NULL --", "1' AND '1'='1"]
        
        for payload in test_payloads:
            # استخدام معلمة 'id' كمثال
            test_url = base_url + "?id=" + urllib.parse.quote(payload)
            resp = requests.get(test_url, timeout=10, headers={'User-Agent': 'SecurityBot-PoC'})
            
            # التحقق من وجود أخطاء SQL نموذجية أو تغير في الاستجابة
            if "syntax" in resp.text.lower() or "mysql" in resp.text.lower() or "sql" in resp.text.lower():
                result["success"] = True
                result["proof"] = f"SQL error detected with payload: {payload}"
                result["details"] = f"Tested URL: {test_url}\nPossible SQL injection point."
                break
            elif "unclosed" in resp.text.lower():
                result["success"] = True
                result["proof"] = f"Unclosed quote detected with payload: {payload}"
                result["details"] = f"Tested URL: {test_url}"
                break
    except Exception as e:
        result["details"] = f"Error during SQL test: {e}"
    
    if not result["success"]:
        result["proof"] = "No obvious SQL injection detected (may still exist with other parameters)"
        result["details"] = "This does not rule out blind SQL injection."
    return result

def demonstrate_directory_traversal(base_url: str) -> Dict[str, Any]:
    """
    عرض دليل على Directory Traversal عن طريق محاولة قراءة ملفات عامة.
    """
    result = {"success": False, "proof": "", "details": ""}
    try:
        # محاولة قراءة ملفات شائعة
        test_paths = ["../../etc/passwd", "../../../etc/passwd", "../../windows/win.ini"]
        for path in test_paths:
            test_url = base_url + "?file=" + urllib.parse.quote(path)
            resp = requests.get(test_url, timeout=10, headers={'User-Agent': 'SecurityBot-PoC'})
            if "root" in resp.text.lower() or "admin" in resp.text.lower():
                result["success"] = True
                result["proof"] = f"Directory traversal detected with: {path}"
                result["details"] = f"Tested URL: {test_url}"
                break
    except Exception as e:
        result["details"] = f"Error during traversal test: {e}"
    
    if not result["success"]:
        result["proof"] = "No obvious directory traversal detected."
        result["details"] = "This does not rule out other path traversal vectors."
    return result

# ─────────────────────────────────────────────
# PDF Report Generation (with exploit results)
# ─────────────────────────────────────────────

def generate_pdf_report(data: Dict[str, Any], exploit_results: Optional[List[Dict]] = None) -> bytes:
    from io import BytesIO
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    disclaimer_style = ParagraphStyle(
        'Disclaimer',
        parent=styles['Normal'],
        fontSize=8,
        textColor=colors.grey,
        alignment=0
    )
    story.append(Paragraph(
        "⚠️ DISCLAIMER: This report is generated from PASSIVE, READ-ONLY scanning. "
        "Any exploit tests performed were NON-DESTRUCTIVE and authorized. "
        "The developer assumes no liability for any misuse.",
        disclaimer_style
    ))
    story.append(Spacer(1, 0.2 * inch))

    title_style = ParagraphStyle(
        'Title',
        parent=styles['Title'],
        fontSize=24,
        textColor=colors.blue,
        alignment=1
    )
    story.append(Paragraph("🔐 Security Scan Report", title_style))
    story.append(Spacer(1, 0.25 * inch))

    info_style = styles['Normal']
    story.append(Paragraph(f"<b>Target URL:</b> {data.get('target_url', 'N/A')}", info_style))
    story.append(Paragraph(f"<b>Scan Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", info_style))
    story.append(Paragraph(f"<b>Status:</b> {data.get('status', 'N/A')}", info_style))
    story.append(Spacer(1, 0.25 * inch))

    # Security Headers
    story.append(Paragraph("<b>Security Headers Analysis</b>", styles['Heading2']))
    headers_data = data.get('security_headers', {})
    for check in headers_data.get('checks', []):
        icon = "✅" if check.get('passed') else "❌"
        status_text = "Enabled" if check.get('passed') else "Not enabled"
        value = f" ({check.get('value', '')})" if check.get('value') else ""
        story.append(Paragraph(f"{icon} <b>{check.get('name')}:</b> {status_text}{value}", info_style))
    
    story.append(Paragraph(f"<b>Score:</b> {headers_data.get('score', 0)}/{headers_data.get('max_score', 6)}", info_style))
    story.append(Spacer(1, 0.2 * inch))

    # SSL
    ssl_data = data.get('ssl', {})
    if ssl_data.get('valid'):
        story.append(Paragraph("<b>✅ SSL/TLS: Valid</b>", styles['Heading2']))
        details = ssl_data.get('details', {})
        story.append(Paragraph(f"<b>Expires in:</b> {details.get('expiry_days', 'N/A')} days", info_style))
        story.append(Paragraph(f"<b>TLS Version:</b> {details.get('tls_version', 'N/A')}", info_style))
        story.append(Paragraph(f"<b>Cipher:</b> {details.get('cipher', 'N/A')}", info_style))
    else:
        story.append(Paragraph("<b>❌ SSL/TLS: Invalid or Not Available</b>", styles['Heading2']))
    story.append(Spacer(1, 0.2 * inch))

    # Open Ports
    ports = data.get('open_ports', [])
    if ports:
        story.append(Paragraph(f"<b>Open Ports:</b> {', '.join(map(str, ports))}", info_style))
    else:
        story.append(Paragraph("<b>Open Ports:</b> None found", info_style))
    story.append(Spacer(1, 0.2 * inch))

    # Sensitive Files
    files = data.get('sensitive_files', [])
    if files:
        story.append(Paragraph("<b>Sensitive Files Found:</b>", info_style))
        for f in files:
            story.append(Paragraph(f"  • {f}", info_style))
    else:
        story.append(Paragraph("<b>Sensitive Files:</b> None found", info_style))
    story.append(Spacer(1, 0.2 * inch))

    # Technologies
    techs = data.get('technologies', [])
    if techs:
        story.append(Paragraph("<b>Technologies:</b>", info_style))
        for t in techs:
            story.append(Paragraph(f"  • {t}", info_style))
    story.append(Spacer(1, 0.2 * inch))

    # Exploit Results
    if exploit_results:
        story.append(Paragraph("<b>🚨 Vulnerability Assessment (PoC)</b>", styles['Heading2']))
        for vuln in exploit_results:
            story.append(Paragraph(f"<b>Type:</b> {vuln.get('type', 'Unknown')}", info_style))
            story.append(Paragraph(f"<b>Severity:</b> {vuln.get('severity', 'unknown')}", info_style))
            story.append(Paragraph(f"<b>Proof:</b> {vuln.get('proof', 'N/A')}", info_style))
            if vuln.get('details'):
                story.append(Paragraph(f"<b>Details:</b> {vuln.get('details', '')}", info_style))
            story.append(Spacer(1, 0.1 * inch))

    # Recommendations
    missing = data.get('missing_headers', [])
    if missing:
        story.append(Paragraph("<b>Recommendations:</b>", styles['Heading2']))
        for rec in missing:
            story.append(Paragraph(f"• {rec}", info_style))
    else:
        story.append(Paragraph("<b>✅ All security headers are properly configured!</b>", info_style))
    story.append(Spacer(1, 0.2 * inch))

    # Final Disclaimer
    story.append(Spacer(1, 0.5 * inch))
    story.append(Paragraph(
        "─" * 50,
        info_style
    ))
    story.append(Paragraph(
        "⚠️ <b>FINAL DISCLAIMER:</b> This scan was performed using PASSIVE techniques only. "
        "Any exploit tests were NON-DESTRUCTIVE and authorized. "
        "The user is solely responsible for ensuring they have authorization to test the target.",
        info_style
    ))

    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()

# ─────────────────────────────────────────────
# Perform Full Scan with Vulnerability Detection
# ─────────────────────────────────────────────

def perform_full_scan(target_url: str) -> Dict[str, Any]:
    result = {
        "target_url": target_url,
        "status": None,
        "security_headers": {},
        "ssl": {},
        "open_ports": [],
        "sensitive_files": [],
        "technologies": [],
        "robots_txt": (False, None),
        "missing_headers": []
    }

    try:
        headers = {'User-Agent': 'SecurityScannerBot/1.0 (PRO Version - Passive Only)'}
        response = requests.get(target_url, timeout=10, allow_redirects=True, headers=headers, verify=True, stream=True)
        _ = response.content[:2 * 1024 * 1024]

        result["status"] = response.status_code
        
        headers_analysis = analyze_security_headers(response.headers)
        result["security_headers"] = headers_analysis
        result["missing_headers"] = headers_analysis.get("missing", [])

        hostname = urlparse(target_url).hostname
        result["ssl"] = analyze_ssl_certificate(hostname)
        result["open_ports"] = scan_open_ports(hostname)
        result["sensitive_files"] = detect_sensitive_files(target_url)
        result["technologies"] = detect_technologies(target_url)
        result["robots_txt"] = check_robots_txt(target_url)

    except Exception as e:
        result["error"] = str(e)

    return result

# ─────────────────────────────────────────────
# Bot Commands
# ─────────────────────────────────────────────

@bot.message_handler(commands=['start'])
def start_cmd(message):
    user_id = message.from_user.id
    
    if not has_accepted_terms(user_id):
        disclaimer_text = (
            "⚠️ <b>LEGAL DISCLAIMER</b>\n\n"
            "This bot performs <b>ONLY PASSIVE, READ-ONLY</b> scanning by default.\n"
            "The exploit feature is <b>NON-DESTRUCTIVE</b> and requires explicit authorization.\n\n"
            "✅ No data is modified or deleted\n"
            "✅ No malicious payloads are sent\n"
            "✅ Only READ-ONLY checks are performed\n\n"
            "You may ONLY test websites you OWN or have EXPLICIT PERMISSION.\n"
            "Unauthorized testing is ILLEGAL.\n\n"
            "The developer assumes NO LIABILITY for any misuse.\n\n"
            "Type <b>/accept</b> to confirm."
        )
        bot.reply_to(message, disclaimer_text, parse_mode="HTML")
        return
    
    license_info = get_user_license(user_id)
    
    if license_info and license_info["expires_at"] > int(time.time()):
        expires = datetime.fromtimestamp(license_info["expires_at"]).strftime('%Y-%m-%d %H:%M')
        text = (
            "🔐 <b>Security Scanner Bot PRO</b>\n\n"
            f"✅ <b>License:</b> Active\n"
            f"📅 <b>Expires:</b> {expires}\n\n"
            "Send me a website URL to perform a full security scan.\n\n"
            "<b>Available Commands:</b>\n"
            "/scan <url> - Full security scan\n"
            "/exploit <url> - Run vulnerability PoC (requires confirmation)\n"
            "/schedule <url> <frequency> - Schedule scan\n"
            "/history - View scan history\n"
            "/report <id> - Generate PDF report\n"
            "/help - Show help\n"
            "/disclaimer - Show legal disclaimer"
        )
    else:
        text = (
            "🔐 <b>Security Scanner Bot PRO</b>\n\n"
            "This is the PRO version with advanced security scanning features.\n\n"
            "To activate, send your license key:\n"
            "<code>/activate YOUR_LICENSE_KEY</code>"
        )
    bot.reply_to(message, text, parse_mode="HTML")

@bot.message_handler(commands=['accept'])
def accept_terms_cmd(message):
    user_id = message.from_user.id
    record_terms_acceptance(user_id)
    bot.reply_to(
        message,
        "✅ You have accepted the terms.\n\n"
        "You can now use the bot. Send /start to begin.",
        parse_mode="HTML"
    )

@bot.message_handler(commands=['disclaimer'])
def disclaimer_cmd(message):
    text = (
        "⚠️ <b>LEGAL DISCLAIMER</b>\n\n"
        "This bot performs <b>ONLY PASSIVE, READ-ONLY</b> scanning by default.\n\n"
        "<b>What this bot DOES NOT do:</b>\n"
        "❌ Send exploit payloads\n"
        "❌ Attack or harm websites\n"
        "❌ Modify or delete data\n"
        "❌ Contain malicious code\n\n"
        "<b>What this bot DOES:</b>\n"
        "✅ Read security headers\n"
        "✅ Check SSL certificate details\n"
        "✅ Detect open ports (simple connection test)\n"
        "✅ Identify sensitive files (HTTP status check)\n"
        "✅ Detect technologies (header/content analysis)\n\n"
        "<b>EXPLOIT FEATURE:</b>\n"
        "• Performs NON-DESTRUCTIVE proof-of-concept tests\n"
        "• Only reads responses, never modifies data\n"
        "• Requires explicit user confirmation\n\n"
        "<b>Legal Requirements:</b>\n"
        "• You must own the target website\n"
        "• Or have explicit written permission\n"
        "• Unauthorized testing is ILLEGAL\n\n"
        "<b>Liability:</b>\n"
        "The developer assumes NO LIABILITY for any misuse.\n"
        "You are SOLELY RESPONSIBLE for your actions.\n\n"
        "<code>By using this bot, you agree to these terms.</code>"
    )
    bot.reply_to(message, text, parse_mode="HTML")

@bot.message_handler(commands=['activate'])
def activate_cmd(message):
    user_id = message.from_user.id
    args = message.text.split()
    if len(args) < 2:
        bot.reply_to(message, "⚠️ Usage: <code>/activate YOUR_LICENSE_KEY</code>", parse_mode="HTML")
        return
    
    license_key = args[1]
    valid, expires_at = verify_license(user_id, license_key)
    
    if valid:
        save_user_license(user_id, license_key, expires_at)
        expires = datetime.fromtimestamp(expires_at).strftime('%Y-%m-%d %H:%M')
        bot.reply_to(
            message,
            f"✅ <b>License activated successfully!</b>\n\n"
            f"📅 Expires: {expires}\n\n"
            f"🔓 You now have access to all PRO features.\n\n"
            f"⚠️ Remember: Only test websites you own or have permission to test.",
            parse_mode="HTML"
        )
    else:
        bot.reply_to(message, "❌ Invalid license key. Please check and try again.")

@bot.message_handler(commands=['scan'])
def scan_cmd(message):
    user_id = message.from_user.id
    license_info = get_user_license(user_id)
    
    if not license_info or license_info["expires_at"] < int(time.time()):
        bot.reply_to(message, "❌ Your license has expired. Please activate with <code>/activate</code>", parse_mode="HTML")
        return
    
    args = message.text.split()
    if len(args) < 2:
        bot.reply_to(message, "⚠️ Usage: <code>/scan https://example.com</code>", parse_mode="HTML")
        return
    
    target = args[1].strip()
    validated_url, error = validate_url(target)
    if error:
        bot.reply_to(message, error, parse_mode="HTML")
        return
    
    status_msg = bot.reply_to(message, "⏳ Performing passive security scan... (READ-ONLY)")
    
    try:
        result = perform_full_scan(validated_url)
        
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute(
            "INSERT INTO scan_history (user_id, target_url, scan_date, result) VALUES (?, ?, ?, ?)",
            (user_id, validated_url, int(time.time()), json.dumps(result))
        )
        scan_id = c.lastrowid
        conn.commit()
        conn.close()
        
        report = format_scan_report(result)
        bot.edit_message_text(report, chat_id=message.chat.id, message_id=status_msg.message_id, parse_mode="HTML")
        
        # Detect vulnerabilities
        vulns = detect_vulnerabilities(result)
        if vulns:
            markup = types.InlineKeyboardMarkup(row_width=1)
            markup.add(types.InlineKeyboardButton("🚨 Run Vulnerability PoC", callback_data=f"poc_{scan_id}"))
            bot.send_message(message.chat.id, "🚨 Potential vulnerabilities detected. Run PoC?", reply_markup=markup)
        else:
            markup = types.InlineKeyboardMarkup()
            markup.add(types.InlineKeyboardButton("📄 Download PDF Report", callback_data=f"pdf_{scan_id}"))
            bot.send_message(message.chat.id, "📄 No vulnerabilities found. PDF report available.", reply_markup=markup)
        
    except Exception as e:
        logger.error(f"Scan error: {e}")
        bot.edit_message_text(f"❌ Error: {escape_html(str(e))}", chat_id=message.chat.id, message_id=status_msg.message_id, parse_mode="HTML")

@bot.message_handler(commands=['exploit'])
def exploit_cmd(message):
    """
    تشغيل اختبار الاستغلال (PoC) مع تحذير مسبق.
    """
    user_id = message.from_user.id
    license_info = get_user_license(user_id)
    
    if not license_info or license_info["expires_at"] < int(time.time()):
        bot.reply_to(message, "❌ Your license has expired.", parse_mode="HTML")
        return
    
    args = message.text.split()
    if len(args) < 2:
        bot.reply_to(message, "⚠️ Usage: <code>/exploit https://example.com</code>", parse_mode="HTML")
        return
    
    target = args[1].strip()
    validated_url, error = validate_url(target)
    if error:
        bot.reply_to(message, error, parse_mode="HTML")
        return
    
    # Show warning
    warning_text = (
        "⚠️ <b>EXPLOIT MODE WARNING</b>\n\n"
        "You are about to run NON-DESTRUCTIVE proof-of-concept tests.\n\n"
        "<b>What will happen:</b>\n"
        "• Simple parameter injection (GET parameters)\n"
        "• File path checks (read-only)\n"
        "• No data will be modified or deleted\n"
        "• No malicious payloads will be sent\n\n"
        "<b>You MUST have:</b>\n"
        "• Ownership of the target\n"
        "• OR explicit written permission\n\n"
        "⚠️ Unauthorized testing is ILLEGAL.\n\n"
        "Type <b>/confirm_exploit</b> to proceed."
    )
    bot.reply_to(message, warning_text, parse_mode="HTML")
    
    # Save pending exploit request
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute(
        "INSERT OR REPLACE INTO temp (user_id, target_url) VALUES (?, ?)",
        (user_id, validated_url)
    )
    conn.commit()
    conn.close()

@bot.message_handler(commands=['confirm_exploit'])
def confirm_exploit_cmd(message):
    """
    تأكيد تنفيذ الاستغلال.
    """
    user_id = message.from_user.id
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT target_url FROM temp WHERE user_id = ?", (user_id,))
    row = c.fetchone()
    if not row:
        bot.reply_to(message, "❌ No pending exploit request. Use <code>/exploit</code> first.", parse_mode="HTML")
        conn.close()
        return
    
    target_url = row[0]
    c.execute("DELETE FROM temp WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()
    
    status_msg = bot.reply_to(message, "⏳ Running non-destructive PoC tests...")
    
    try:
        # Run PoC tests
        poc_results = []
        
        # Test XSS
        xss_result = demonstrate_xss_vulnerability(target_url)
        if xss_result["success"]:
            poc_results.append({
                "type": "XSS (Cross-Site Scripting)",
                "severity": "high",
                "proof": xss_result.get("proof", "Possible XSS"),
                "details": xss_result.get("details", "")
            })
        
        # Test SQL Injection
        sql_result = demonstrate_sql_injection_vulnerability(target_url)
        if sql_result["success"]:
            poc_results.append({
                "type": "SQL Injection",
                "severity": "critical",
                "proof": sql_result.get("proof", "Possible SQL Injection"),
                "details": sql_result.get("details", "")
            })
        
        # Test Directory Traversal
        trav_result = demonstrate_directory_traversal(target_url)
        if trav_result["success"]:
            poc_results.append({
                "type": "Directory Traversal",
                "severity": "high",
                "proof": trav_result.get("proof", "Possible Directory Traversal"),
                "details": trav_result.get("details", "")
            })
        
        # Log the exploit attempt
        log_exploit(user_id, target_url, "PoC", json.dumps(poc_results))
        
        if poc_results:
            result_text = "🚨 <b>Vulnerability Proof-of-Concept Results</b>\n\n"
            for vuln in poc_results:
                result_text += f"<b>Type:</b> {vuln['type']}\n"
                result_text += f"<b>Severity:</b> {vuln['severity']}\n"
                result_text += f"<b>Proof:</b> {vuln['proof']}\n"
                if vuln.get('details'):
                    result_text += f"<b>Details:</b> {vuln['details']}\n"
                result_text += "\n"
            result_text += "\n⚠️ <i>These are NON-DESTRUCTIVE tests. No data was modified.</i>"
        else:
            result_text = "✅ No obvious vulnerabilities found during PoC tests.\n\n"
            result_text += "⚠️ This does not guarantee the absence of all vulnerabilities."
        
        bot.edit_message_text(result_text, chat_id=message.chat.id, message_id=status_msg.message_id, parse_mode="HTML")
        
    except Exception as e:
        logger.error(f"Exploit error: {e}")
        bot.edit_message_text(f"❌ Error: {escape_html(str(e))}", chat_id=message.chat.id, message_id=status_msg.message_id, parse_mode="HTML")

@bot.message_handler(commands=['history'])
def history_cmd(message):
    user_id = message.from_user.id
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute(
        "SELECT id, target_url, scan_date FROM scan_history WHERE user_id = ? ORDER BY scan_date DESC LIMIT 10",
        (user_id,)
    )
    rows = c.fetchall()
    conn.close()
    
    if not rows:
        bot.reply_to(message, "📭 No scan history found.")
        return
    
    text = "📜 <b>Recent Scans</b>\n\n"
    for row in rows:
        date_str = datetime.fromtimestamp(row[2]).strftime('%Y-%m-%d %H:%M')
        text += f"• <b>{date_str}</b> - <code>{row[1]}</code> [ID: {row[0]}]\n"
    
    bot.reply_to(message, text, parse_mode="HTML")

@bot.message_handler(commands=['schedule'])
def schedule_cmd(message):
    user_id = message.from_user.id
    license_info = get_user_license(user_id)
    
    if not license_info or license_info["expires_at"] < int(time.time()):
        bot.reply_to(message, "❌ Your license has expired.", parse_mode="HTML")
        return
    
    args = message.text.split()
    if len(args) < 3:
        bot.reply_to(message, "⚠️ Usage: <code>/schedule https://example.com daily</code>\nFrequencies: hourly, daily, weekly", parse_mode="HTML")
        return
    
    target = args[1].strip()
    frequency = args[2].strip().lower()
    if frequency not in ['hourly', 'daily', 'weekly']:
        bot.reply_to(message, "❌ Frequency must be: hourly, daily, or weekly")
        return
    
    validated_url, error = validate_url(target)
    if error:
        bot.reply_to(message, error, parse_mode="HTML")
        return
    
    now = int(time.time())
    if frequency == 'hourly':
        next_run = now + 3600
    elif frequency == 'daily':
        next_run = now + 86400
    else:
        next_run = now + 604800
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute(
        "INSERT INTO scheduled_scans (user_id, target_url, frequency, next_run) VALUES (?, ?, ?, ?)",
        (user_id, validated_url, frequency, next_run)
    )
    conn.commit()
    conn.close()
    
    bot.reply_to(message, f"✅ Scan scheduled for <code>{validated_url}</code> every <b>{frequency}</b>.", parse_mode="HTML")

@bot.message_handler(commands=['help'])
def help_cmd(message):
    text = (
        "🔐 <b>Security Scanner Bot PRO - Help</b>\n\n"
        "<b>Commands:</b>\n"
        "/start - Show welcome message\n"
        "/activate <key> - Activate license\n"
        "/scan <url> - Perform full security scan\n"
        "/exploit <url> - Run PoC tests (requires confirmation)\n"
        "/schedule <url> <frequency> - Schedule scans\n"
        "/history - View scan history\n"
        "/report <id> - Download PDF report\n"
        "/disclaimer - Show legal disclaimer\n"
        "/help - Show this help\n\n"
        "<b>Features:</b>\n"
        "• Security headers (HSTS, CSP, X-Frame-Options, etc.)\n"
        "• SSL/TLS certificate analysis\n"
        "• Open port scanning\n"
        "• Sensitive file detection\n"
        "• Technology fingerprinting\n"
        "• PDF reports\n"
        "• Scheduled scans\n"
        "• Non-destructive vulnerability PoC\n\n"
        "⚠️ <b>REMINDER:</b> PASSIVE SCANNING ONLY by default. "
        "Exploit mode is NON-DESTRUCTIVE and requires explicit confirmation.\n"
        "Only test websites you own or have permission to test.\n\n"
        "📧 Support: support@example.com"
    )
    bot.reply_to(message, text, parse_mode="HTML")

@bot.callback_query_handler(func=lambda call: call.data.startswith('pdf_'))
def handle_pdf_callback(call):
    user_id = call.from_user.id
    scan_id = int(call.data.replace('pdf_', ''))
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT target_url, result FROM scan_history WHERE id = ? AND user_id = ?", (scan_id, user_id))
    row = c.fetchone()
    conn.close()
    
    if not row:
        bot.answer_callback_query(call.id, "❌ Scan not found.", show_alert=True)
        return
    
    try:
        data = json.loads(row[1])
        pdf_bytes = generate_pdf_report(data)
        bot.send_document(
            call.message.chat.id,
            (f"scan_report_{scan_id}.pdf", pdf_bytes),
            caption=f"📄 Passive scan report for {row[0]}"
        )
        bot.answer_callback_query(call.id, "✅ PDF report sent!")
    except Exception as e:
        bot.answer_callback_query(call.id, f"❌ Error: {e}", show_alert=True)

@bot.callback_query_handler(func=lambda call: call.data.startswith('poc_'))
def handle_poc_callback(call):
    user_id = call.from_user.id
    scan_id = int(call.data.replace('poc_', ''))
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT target_url, result FROM scan_history WHERE id = ? AND user_id = ?", (scan_id, user_id))
    row = c.fetchone()
    conn.close()
    
    if not row:
        bot.answer_callback_query(call.id, "❌ Scan not found.", show_alert=True)
        return
    
    target_url = row[0]
    
    # Show warning before proceeding
    warning_text = (
        "⚠️ <b>EXPLOIT MODE WARNING</b>\n\n"
        "You are about to run NON-DESTRUCTIVE proof-of-concept tests.\n\n"
        "<b>What will happen:</b>\n"
        "• Simple parameter injection (GET parameters)\n"
        "• File path checks (read-only)\n"
        "• No data will be modified or deleted\n\n"
        "<b>You MUST have:</b>\n"
        "• Ownership of the target\n"
        "• OR explicit written permission\n\n"
        "⚠️ Unauthorized testing is ILLEGAL.\n\n"
        "Do you want to proceed?"
    )
    
    markup = types.InlineKeyboardMarkup(row_width=2)
    markup.add(
        types.InlineKeyboardButton("✅ Yes, Proceed", callback_data=f"confirm_poc_{scan_id}"),
        types.InlineKeyboardButton("❌ Cancel", callback_data="cancel_poc")
    )
    bot.send_message(call.message.chat.id, warning_text, parse_mode="HTML", reply_markup=markup)
    bot.answer_callback_query(call.id)

@bot.callback_query_handler(func=lambda call: call.data.startswith('confirm_poc_'))
def confirm_poc_callback(call):
    user_id = call.from_user.id
    scan_id = int(call.data.replace('confirm_poc_', ''))
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT target_url, result FROM scan_history WHERE id = ? AND user_id = ?", (scan_id, user_id))
    row = c.fetchone()
    conn.close()
    
    if not row:
        bot.answer_callback_query(call.id, "❌ Scan not found.", show_alert=True)
        return
    
    target_url = row[0]
    
    status_msg = bot.send_message(call.message.chat.id, "⏳ Running non-destructive PoC tests...")
    
    try:
        # Run PoC tests
        poc_results = []
        
        xss_result = demonstrate_xss_vulnerability(target_url)
        if xss_result["success"]:
            poc_results.append({
                "type": "XSS (Cross-Site Scripting)",
                "severity": "high",
                "proof": xss_result.get("proof", "Possible XSS"),
                "details": xss_result.get("details", "")
            })
        
        sql_result = demonstrate_sql_injection_vulnerability(target_url)
        if sql_result["success"]:
            poc_results.append({
                "type": "SQL Injection",
                "severity": "critical",
                "proof": sql_result.get("proof", "Possible SQL Injection"),
                "details": sql_result.get("details", "")
            })
        
        trav_result = demonstrate_directory_traversal(target_url)
        if trav_result["success"]:
            poc_results.append({
                "type": "Directory Traversal",
                "severity": "high",
                "proof": trav_result.get("proof", "Possible Directory Traversal"),
                "details": trav_result.get("details", "")
            })
        
        log_exploit(user_id, target_url, "PoC", json.dumps(poc_results))
        
        if poc_results:
            result_text = "🚨 <b>Vulnerability Proof-of-Concept Results</b>\n\n"
            for vuln in poc_results:
                result_text += f"<b>Type:</b> {vuln['type']}\n"
                result_text += f"<b>Severity:</b> {vuln['severity']}\n"
                result_text += f"<b>Proof:</b> {vuln['proof']}\n"
                if vuln.get('details'):
                    result_text += f"<b>Details:</b> {vuln['details']}\n"
                result_text += "\n"
            result_text += "\n⚠️ <i>These are NON-DESTRUCTIVE tests. No data was modified.</i>"
        else:
            result_text = "✅ No obvious vulnerabilities found during PoC tests.\n\n"
            result_text += "⚠️ This does not guarantee the absence of all vulnerabilities."
        
        bot.edit_message_text(result_text, chat_id=status_msg.chat.id, message_id=status_msg.message_id, parse_mode="HTML")
        bot.answer_callback_query(call.id, "✅ PoC tests completed.")
        
    except Exception as e:
        logger.error(f"Exploit error: {e}")
        bot.edit_message_text(f"❌ Error: {escape_html(str(e))}", chat_id=status_msg.chat.id, message_id=status_msg.message_id, parse_mode="HTML")
        bot.answer_callback_query(call.id, f"❌ Error: {e}", show_alert=True)

@bot.callback_query_handler(func=lambda call: call.data == "cancel_poc")
def cancel_poc_callback(call):
    bot.edit_message_text("❌ PoC tests cancelled.", chat_id=call.message.chat.id, message_id=call.message.message_id)
    bot.answer_callback_query(call.id, "Cancelled.")

# ─────────────────────────────────────────────
# Format Report
# ─────────────────────────────────────────────

def format_scan_report(result: Dict[str, Any]) -> str:
    lines = []
    lines.append("🔐 <b>Security Scan Report</b>\n")
    lines.append("⚠️ <i>Passive, READ-ONLY scan. No payloads sent.</i>\n")
    
    if "error" in result:
        lines.append(f"❌ <b>Error:</b> {result['error']}")
        return "\n".join(lines)
    
    lines.append(f"🌐 <b>Target:</b> <code>{result.get('target_url', 'N/A')}</code>")
    lines.append(f"📡 <b>Status:</b> <code>{result.get('status', 'N/A')}</code>")
    lines.append("")
    lines.append("─" * 30)
    lines.append("🔍 <b>Security Headers Analysis</b>\n")
    
    headers = result.get('security_headers', {})
    for check in headers.get('checks', []):
        icon = "✅" if check.get('passed') else "⚠️"
        status = "Enabled" if check.get('passed') else "Not enabled"
        value = f" ({check.get('value', '')})" if check.get('value') else ""
        lines.append(f"{icon} <b>{check.get('name')}:</b> {status}{value}")
    
    lines.append(f"\n📊 <b>Score:</b> {headers.get('score', 0)}/{headers.get('max_score', 6)}")
    lines.append("")
    lines.append("─" * 30)
    
    ssl = result.get('ssl', {})
    if ssl.get('valid'):
        details = ssl.get('details', {})
        lines.append("🔐 <b>SSL/TLS: Valid</b>")
        lines.append(f"   📅 Expires in: <b>{details.get('expiry_days', 'N/A')}</b> days")
        lines.append(f"   📌 Version: <b>{details.get('tls_version', 'N/A')}</b>")
        lines.append(f"   🔑 Cipher: <code>{details.get('cipher', 'N/A')}</code>")
    else:
        lines.append("🔓 <b>SSL/TLS: Invalid or Not Available</b>")
        if 'error' in ssl:
            lines.append(f"   ⚠️ {ssl['error']}")
    
    lines.append("")
    lines.append("─" * 30)
    
    ports = result.get('open_ports', [])
    if ports:
        lines.append(f"🔌 <b>Open Ports:</b> <code>{', '.join(map(str, ports))}</code>")
    else:
        lines.append("🔌 <b>Open Ports:</b> None found")
    
    lines.append("")
    lines.append("─" * 30)
    
    files = result.get('sensitive_files', [])
    if files:
        lines.append("📂 <b>Sensitive Files Found:</b>")
        for f in files:
            lines.append(f"   • <code>{f}</code>")
    else:
        lines.append("📂 <b>Sensitive Files:</b> None found")
    
    lines.append("")
    lines.append("─" * 30)
    
    techs = result.get('technologies', [])
    if techs:
        lines.append("🛠️ <b>Technologies:</b>")
        for t in techs:
            lines.append(f"   • {t}")
    
    lines.append("")
    lines.append("─" * 30)
    
    robots, robots_content = result.get('robots_txt', (False, None))
    lines.append(f"📄 <b>robots.txt:</b> {'Found' if robots else 'Not found'}")
    
    lines.append("")
    lines.append("─" * 30)
    
    missing = result.get('missing_headers', [])
    if missing:
        lines.append("💡 <b>Recommendations:</b>")
        for rec in missing:
            lines.append(f"• {rec}")
    else:
        lines.append("✅ <b>All security headers are properly configured!</b>")
    
    lines.append("")
    lines.append("─" * 30)
    lines.append("🔒 <i>Passive scan only. No data was modified or exploited.</i>")
    
    return "\n".join(lines)

# ─────────────────────────────────────────────
# Schedule Checker
# ─────────────────────────────────────────────

def check_scheduled_scans():
    now = int(time.time())
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute(
        "SELECT id, user_id, target_url, frequency, next_run FROM scheduled_scans WHERE active = 1 AND next_run <= ?",
        (now,)
    )
    scans = c.fetchall()
    
    for scan in scans:
        scan_id, user_id, target_url, frequency, next_run = scan
        try:
            result = perform_full_scan(target_url)
            c.execute(
                "INSERT INTO scan_history (user_id, target_url, scan_date, result) VALUES (?, ?, ?, ?)",
                (user_id, target_url, int(time.time()), json.dumps(result))
            )
            
            if frequency == 'hourly':
                next_run = now + 3600
            elif frequency == 'daily':
                next_run = now + 86400
            else:
                next_run = now + 604800
            
            c.execute("UPDATE scheduled_scans SET next_run = ? WHERE id = ?", (next_run, scan_id))
            conn.commit()
            
            try:
                bot.send_message(
                    user_id,
                    f"✅ Scheduled passive scan completed for <code>{target_url}</code>",
                    parse_mode="HTML"
                )
            except:
                pass
            
        except Exception as e:
            logger.error(f"Scheduled scan error: {e}")
    
    conn.close()

def run_schedule_checker():
    def checker_loop():
        while True:
            try:
                check_scheduled_scans()
                time.sleep(60)
            except Exception as e:
                logger.error(f"Schedule checker error: {e}")
                time.sleep(300)
    
    thread = threading.Thread(target=checker_loop, daemon=True)
    thread.start()

# ─────────────────────────────────────────────
# Message Handler
# ─────────────────────────────────────────────

@bot.message_handler(func=lambda m: True)
def handle_url(message):
    target = message.text.strip()
    if not re.match(r'^https?://', target):
        return
    
    user_id = message.from_user.id
    license_info = get_user_license(user_id)
    
    if not license_info or license_info["expires_at"] < int(time.time()):
        bot.reply_to(message, "❌ Your license has expired. Please activate with <code>/activate</code>", parse_mode="HTML")
        return
    
    msg = type('obj', (object,), {'text': f'/scan {target}', 'chat': message.chat, 'from_user': message.from_user})()
    scan_cmd(msg)

# ─────────────────────────────────────────────
# Start Bot
# ─────────────────────────────────────────────

if __name__ == "__main__":
    logger.info("🔐 Security Scanner Bot PRO is running (PASSIVE + NON-DESTRUCTIVE PoC)...")
    run_schedule_checker()
    
    try:
        bot.infinity_polling(skip_pending=True)
    except KeyboardInterrupt:
        logger.info("Bot stopped by user.")
    except Exception as e:
        logger.error(f"Fatal error: {e}")