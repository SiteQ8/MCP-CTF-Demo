#!/usr/bin/env python3
"""
MCP Security Tools Server
SANS Cloud Exchange Summit Demo — Ali AlEnezi (@SiteQ8)

A Model Context Protocol server that exposes security reconnaissance
and vulnerability assessment tools for AI agent consumption.

Usage:
  python3 mcp_security_server.py [--port 8080]
  
Tools exposed:
  1. recon_dns       - DNS enumeration (subdomains, records)
  2. recon_ports     - Port scanning (TCP connect)
  3. recon_headers   - HTTP header security analysis
  4. vuln_ssl        - SSL/TLS configuration check
  5. vuln_headers    - Security header assessment (OWASP)
  6. vuln_tech       - Technology fingerprinting
  7. exploit_chain   - Chain findings into attack paths
  8. report_generate - Generate structured findings report
"""

import json
import socket
import ssl
import subprocess
import sys
import urllib.request
import urllib.error
import argparse
import re
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime

VERSION = "1.0"

# ═══ TOOL IMPLEMENTATIONS ═══

def recon_dns(domain):
    """DNS enumeration — subdomains, MX, TXT, NS records"""
    results = {"domain": domain, "records": {}, "subdomains": []}
    
    for rtype in ["A", "MX", "TXT", "NS", "CNAME", "AAAA"]:
        try:
            out = subprocess.check_output(
                ["dig", "+short", rtype, domain],
                timeout=10, stderr=subprocess.DEVNULL
            ).decode().strip()
            if out:
                results["records"][rtype] = out.split("\n")
        except Exception:
            pass
    
    # Common subdomain check
    common_subs = ["www", "mail", "api", "dev", "staging", "admin", "vpn",
                   "ftp", "ssh", "test", "blog", "shop", "app", "portal",
                   "cdn", "media", "docs", "status", "git", "ci"]
    for sub in common_subs:
        try:
            socket.getaddrinfo(f"{sub}.{domain}", None, socket.AF_INET, 
                             socket.SOCK_STREAM, 0, socket.AI_CANONNAME)
            results["subdomains"].append(f"{sub}.{domain}")
        except socket.gaierror:
            pass
    
    results["timestamp"] = datetime.now().isoformat()
    return results

def recon_ports(target, ports=None):
    """TCP port scan — top ports"""
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995,
                 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200]
    
    results = {"target": target, "open_ports": [], "closed": 0}
    
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5)
            result = sock.connect_ex((target, port))
            if result == 0:
                service = get_service_name(port)
                banner = grab_banner(target, port)
                results["open_ports"].append({
                    "port": port,
                    "service": service,
                    "banner": banner,
                    "state": "open"
                })
            else:
                results["closed"] += 1
            sock.close()
        except Exception:
            results["closed"] += 1
    
    results["timestamp"] = datetime.now().isoformat()
    return results

def get_service_name(port):
    services = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
        993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
        3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
        6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9200: "Elasticsearch"
    }
    return services.get(port, f"unknown-{port}")

def grab_banner(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((target, port))
        if port in [80, 8080]:
            sock.send(b"HEAD / HTTP/1.0\r\nHost: " + target.encode() + b"\r\n\r\n")
        banner = sock.recv(1024).decode(errors="ignore").strip()[:200]
        sock.close()
        return banner
    except Exception:
        return ""

def recon_headers(url):
    """HTTP header security analysis"""
    results = {"url": url, "headers": {}, "security_issues": [], "score": 0}
    
    try:
        req = urllib.request.Request(url, method="HEAD")
        req.add_header("User-Agent", "MCP-Security-Scanner/1.0")
        resp = urllib.request.urlopen(req, timeout=10)
        
        for key, val in resp.headers.items():
            results["headers"][key] = val
        
        results["status_code"] = resp.status
        
        # Security header checks
        security_headers = {
            "Strict-Transport-Security": "HSTS not set — vulnerable to downgrade attacks",
            "Content-Security-Policy": "CSP not set — vulnerable to XSS",
            "X-Frame-Options": "X-Frame-Options not set — vulnerable to clickjacking",
            "X-Content-Type-Options": "X-Content-Type-Options not set — MIME sniffing risk",
            "X-XSS-Protection": "X-XSS-Protection not set",
            "Referrer-Policy": "Referrer-Policy not set — information leakage risk",
            "Permissions-Policy": "Permissions-Policy not set"
        }
        
        max_score = len(security_headers)
        current = 0
        
        for header, issue in security_headers.items():
            if header.lower() not in [h.lower() for h in results["headers"]]:
                results["security_issues"].append({
                    "severity": "HIGH" if header in ["Strict-Transport-Security", "Content-Security-Policy"] else "MEDIUM",
                    "finding": issue
                })
            else:
                current += 1
        
        # Check for information disclosure
        for header in ["Server", "X-Powered-By", "X-AspNet-Version"]:
            if header in results["headers"]:
                results["security_issues"].append({
                    "severity": "LOW",
                    "finding": f"{header} header exposes: {results['headers'][header]}"
                })
        
        results["score"] = round(current / max_score * 100)
        
    except Exception as e:
        results["error"] = str(e)
    
    results["timestamp"] = datetime.now().isoformat()
    return results

def vuln_ssl(host, port=443):
    """SSL/TLS configuration assessment"""
    results = {"host": host, "port": port, "issues": [], "certificate": {}}
    
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                results["protocol"] = ssock.version()
                results["cipher"] = ssock.cipher()
                
                if cert:
                    results["certificate"] = {
                        "subject": str(cert.get("subject", "")),
                        "issuer": str(cert.get("issuer", "")),
                        "notBefore": cert.get("notBefore", ""),
                        "notAfter": cert.get("notAfter", ""),
                        "serialNumber": cert.get("serialNumber", "")
                    }
                
                # Check protocol version
                proto = ssock.version()
                if proto in ["TLSv1", "TLSv1.1", "SSLv3"]:
                    results["issues"].append({
                        "severity": "CRITICAL",
                        "finding": f"Outdated protocol: {proto}"
                    })
                
                # Check cipher strength
                cipher_name = ssock.cipher()[0] if ssock.cipher() else ""
                if "RC4" in cipher_name or "DES" in cipher_name:
                    results["issues"].append({
                        "severity": "HIGH",
                        "finding": f"Weak cipher: {cipher_name}"
                    })
                    
    except Exception as e:
        results["error"] = str(e)
    
    results["timestamp"] = datetime.now().isoformat()
    return results

def exploit_chain(findings):
    """Analyze findings and suggest attack chains"""
    chains = []
    
    open_ports = findings.get("open_ports", [])
    header_issues = findings.get("header_issues", [])
    ssl_issues = findings.get("ssl_issues", [])
    subdomains = findings.get("subdomains", [])
    
    # Chain 1: Subdomain takeover
    if len(subdomains) > 5:
        chains.append({
            "name": "Subdomain Enumeration → Takeover",
            "risk": "HIGH",
            "steps": [
                f"Discovered {len(subdomains)} subdomains",
                "Check for dangling DNS (CNAME to deprovisioned services)",
                "Attempt subdomain takeover on orphaned entries",
                "Deploy phishing page on taken-over subdomain"
            ],
            "mitre": "T1583.001 — Acquire Infrastructure: Domains"
        })
    
    # Chain 2: Service exploitation
    risky_ports = [p for p in open_ports if p.get("port") in [21, 23, 3389, 6379, 9200]]
    if risky_ports:
        chains.append({
            "name": "Exposed Service → Credential Attack → Lateral Movement",
            "risk": "CRITICAL",
            "steps": [
                f"Found {len(risky_ports)} high-risk services: {[p['service'] for p in risky_ports]}",
                "Attempt default/weak credentials",
                "Exploit known CVEs for identified versions",
                "Pivot to internal network"
            ],
            "mitre": "T1190 — Exploit Public-Facing Application"
        })
    
    # Chain 3: Web application
    if any(p.get("port") in [80, 443, 8080, 8443] for p in open_ports):
        chains.append({
            "name": "Web Recon → Header Analysis → Application Attack",
            "risk": "HIGH",
            "steps": [
                "Fingerprint web technologies",
                "Identify missing security headers (CSP, HSTS)",
                "Test for OWASP Top 10 vulnerabilities",
                "Exploit XSS/CSRF via missing CSP"
            ],
            "mitre": "T1189 — Drive-by Compromise"
        })
    
    # Chain 4: SSL/TLS
    if ssl_issues:
        chains.append({
            "name": "SSL Weakness → MITM → Credential Intercept",
            "risk": "HIGH",
            "steps": [
                f"Found SSL issues: {[i['finding'] for i in ssl_issues]}",
                "Position for man-in-the-middle attack",
                "Downgrade connection to weak cipher",
                "Intercept credentials or session tokens"
            ],
            "mitre": "T1557 — Adversary-in-the-Middle"
        })
    
    return {
        "attack_chains": chains,
        "total_chains": len(chains),
        "highest_risk": "CRITICAL" if any(c["risk"] == "CRITICAL" for c in chains) else "HIGH",
        "timestamp": datetime.now().isoformat()
    }

def generate_report(target, all_findings):
    """Generate structured security assessment report"""
    report = {
        "title": f"MCP Agent Security Assessment — {target}",
        "generated_by": "SiteQ8-MCP-Agent v1.0",
        "author": "Ali AlEnezi (@SiteQ8)",
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "executive_summary": "",
        "findings": all_findings,
        "risk_rating": "UNKNOWN",
        "recommendations": []
    }
    
    # Calculate risk
    critical = sum(1 for f in all_findings.get("issues", []) if f.get("severity") == "CRITICAL")
    high = sum(1 for f in all_findings.get("issues", []) if f.get("severity") == "HIGH")
    
    if critical > 0:
        report["risk_rating"] = "CRITICAL"
    elif high > 2:
        report["risk_rating"] = "HIGH"
    elif high > 0:
        report["risk_rating"] = "MEDIUM"
    else:
        report["risk_rating"] = "LOW"
    
    report["recommendations"] = [
        "Implement missing security headers (CSP, HSTS, X-Frame-Options)",
        "Disable unnecessary network services",
        "Upgrade to TLS 1.3 where possible",
        "Deploy Web Application Firewall (WAF)",
        "Implement API rate limiting against automated attacks",
        "Enable behavioral detection for AI-speed attack patterns"
    ]
    
    return report

# ═══ MCP SERVER ═══

TOOLS = {
    "recon_dns": {
        "description": "DNS enumeration — discover subdomains, MX, TXT, NS records",
        "parameters": {"domain": {"type": "string", "description": "Target domain"}}
    },
    "recon_ports": {
        "description": "TCP port scan — identify open services",
        "parameters": {"target": {"type": "string", "description": "Target IP or hostname"}}
    },
    "recon_headers": {
        "description": "HTTP security header analysis",
        "parameters": {"url": {"type": "string", "description": "Target URL"}}
    },
    "vuln_ssl": {
        "description": "SSL/TLS configuration assessment",
        "parameters": {"host": {"type": "string", "description": "Target hostname"}}
    },
    "exploit_chain": {
        "description": "Analyze findings and suggest attack chains with MITRE mapping",
        "parameters": {"findings": {"type": "object", "description": "Combined findings from other tools"}}
    },
    "report_generate": {
        "description": "Generate structured security assessment report",
        "parameters": {
            "target": {"type": "string"},
            "findings": {"type": "object"}
        }
    }
}

class MCPHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        
        try:
            request = json.loads(body)
        except json.JSONDecodeError:
            self.send_json({"error": "Invalid JSON"}, 400)
            return
        
        method = request.get("method", "")
        params = request.get("params", {})
        
        if method == "tools/list":
            self.send_json({"tools": [
                {"name": k, **v} for k, v in TOOLS.items()
            ]})
        elif method == "tools/call":
            tool_name = params.get("name", "")
            tool_args = params.get("arguments", {})
            result = self.execute_tool(tool_name, tool_args)
            self.send_json({"result": result})
        else:
            self.send_json({"error": f"Unknown method: {method}"}, 404)
    
    def execute_tool(self, name, args):
        try:
            if name == "recon_dns":
                return recon_dns(args.get("domain", ""))
            elif name == "recon_ports":
                return recon_ports(args.get("target", ""))
            elif name == "recon_headers":
                return recon_headers(args.get("url", ""))
            elif name == "vuln_ssl":
                return vuln_ssl(args.get("host", ""))
            elif name == "exploit_chain":
                return exploit_chain(args.get("findings", {}))
            elif name == "report_generate":
                return generate_report(args.get("target", ""), args.get("findings", {}))
            else:
                return {"error": f"Unknown tool: {name}"}
        except Exception as e:
            return {"error": str(e)}
    
    def send_json(self, data, code=200):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode())
    
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
    
    def log_message(self, format, *args):
        print(f"[MCP] {datetime.now().strftime('%H:%M:%S')} — {format % args}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MCP Security Tools Server")
    parser.add_argument("--port", type=int, default=8080, help="Server port")
    args = parser.parse_args()
    
    print(f"""
╔══════════════════════════════════════════════════╗
║  MCP Security Tools Server v{VERSION}                 ║
║  SANS Cloud Exchange Summit Demo                 ║
║  Ali AlEnezi (@SiteQ8) — NBK Group               ║
╠══════════════════════════════════════════════════╣
║  Tools: {len(TOOLS)} security tools exposed via MCP        ║
║  Port:  {args.port}                                     ║
╚══════════════════════════════════════════════════╝
    """)
    
    server = HTTPServer(("0.0.0.0", args.port), MCPHandler)
    print(f"[MCP] Server running on http://0.0.0.0:{args.port}")
    server.serve_forever()
