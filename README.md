<div align="center">

# 🤖 MCP-CTF-Demo

### I Brought Kali. They Brought AI.
**How MCP Agents Are Rewriting CTFs — and What Banks Must Learn Before Attackers Do**

[![SANS](https://img.shields.io/badge/SANS-Cloud_Exchange_Summit_2026-dc2626?style=flat-square)]()
[![MCP](https://img.shields.io/badge/MCP-Security_Tools-00ff88?style=flat-square)]()
[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?style=flat-square)]()
[![License](https://img.shields.io/badge/license-MIT-gold?style=flat-square)]()

**Live Demo:** [siteq8.github.io/MCP-CTF-Demo](https://siteq8.github.io/MCP-CTF-Demo)

</div>

---

## 💀 The Story

At a recent CTF competition, I arrived prepared — Kali Linux loaded, custom exploit scripts ready. Then I watched competing teams deploy **MCP-connected AI agents** that chained reconnaissance, vulnerability discovery, and exploitation at **machine speed**, capturing flags at **3-5× my rate**.

That moment revealed: the offensive security playbook has been rewritten.

---

## 🔌 What's Inside

### MCP Security Server (`scripts/mcp-server/`)

A Python MCP server exposing 6 security tools:

| Tool | Description |
|------|-------------|
| `recon_dns` | DNS enumeration — subdomains, MX, TXT, NS records |
| `recon_ports` | TCP port scan — top 22 ports, banner grabbing |
| `recon_headers` | HTTP security header analysis (OWASP) |
| `vuln_ssl` | SSL/TLS configuration assessment |
| `exploit_chain` | Attack path analysis with MITRE ATT&CK mapping |
| `report_generate` | Structured findings report |

### Interactive Demo GUI (`docs/`)

6-tab web dashboard for the SANS presentation:

- **📊 Overview** — The CTF story + MCP explanation
- **🔌 MCP Architecture** — Protocol diagram + tool reference
- **🎯 Live Demo** — Simulated AI agent running all 6 tools
- **⚡ Human vs AI** — Side-by-side speed comparison
- **🔗 Attack Chains** — 3 multi-step attack paths with MITRE mapping
- **🛡️ Bank Playbook** — 6-point defense strategy

---

## 🚀 Quick Start

### Run the MCP Server

```bash
git clone https://github.com/SiteQ8/MCP-CTF-Demo.git
cd MCP-CTF-Demo
python3 scripts/mcp-server/mcp_security_server.py --port 8080
```

### Call a Tool

```bash
curl -X POST http://localhost:8080 \
  -H "Content-Type: application/json" \
  -d '{"method":"tools/call","params":{"name":"recon_dns","arguments":{"domain":"example.com"}}}'
```

### List Available Tools

```bash
curl -X POST http://localhost:8080 \
  -H "Content-Type: application/json" \
  -d '{"method":"tools/list"}'
```

---

## 🛡️ 6-Point Banking Defense Playbook

1. **Red Team WITH AI Agents** — Deploy MCP agent pentesters in CI/CD
2. **Assume AI Speed** — Automated containment within 30 seconds
3. **Behavioral Detection** — UEBA over signatures
4. **Secure Your AI Agents** — Zero-trust for MCP servers
5. **Update Threat Models** — Add AI-augmented adversary scenarios
6. **Internal CTFs** — Monthly AI-augmented red team exercises

---

## ⚡ Human vs AI Agent

| Task | Human Pentester | MCP AI Agent |
|------|----------------|--------------|
| DNS Recon | 15-30 min | **0.5 sec** |
| Port Scan | 10-45 min | **2 sec** |
| Header Analysis | 5-10 min | **0.3 sec** |
| SSL Check | 5-10 min | **0.5 sec** |
| Attack Chain Analysis | 1-2 hours | **1 sec** |
| Report Writing | 2-4 hours | **2 sec** |
| **Total** | **4-8 hours** | **~8 seconds** |

---

## 👤 Author

**Ali AlEnezi** · [@SiteQ8](https://github.com/SiteQ8) · [3li.info](https://3li.info)

Security Architecture Principal · National Bank of Kuwait (NBK Group) 🇰🇼

GPEN · GWEB · GDSA · GICSP · GCCC · CMU CISO · PCI DSS Professional
