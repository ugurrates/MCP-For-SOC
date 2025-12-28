# 🛡️ Multi-Source Threat Intelligence MCP Server

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![MCP](https://img.shields.io/badge/MCP-Compatible-green.svg)](https://modelcontextprotocol.io)

**Aviation-focused threat intelligence platform** integrating **9+ threat intelligence sources** for comprehensive IOC (Indicator of Compromise) analysis.

## 🎯 Overview

This MCP (Model Context Protocol) server provides automated, multi-source threat intelligence analysis with:

- ✅ **9+ Intelligence Sources**: VirusTotal, AbuseIPDB, Shodan, AlienVault OTX, Abuse.ch suite, and more
- ✅ **3-Phase Analysis**: Intelligence Gathering → Risk Assessment → Actionable Recommendations
- ✅ **Aviation Security Focus**: Tailored for aviation infrastructure protection
- ✅ **Zero False Positives**: Multi-source validation and risk scoring
- ✅ **Microsoft Defender Integration**: Auto-generated KQL queries for EDR hunting
- ✅ **Async Architecture**: Fast, concurrent API queries

## 🚀 Features

### Supported IOC Types
- **IP Addresses**: IPv4 analysis with geolocation, reputation, and vulnerability data
- **Domains**: DNS, WHOIS, SSL certificate analysis
- **URLs**: Link reputation, phishing detection
- **File Hashes**: MD5, SHA1, SHA256 malware analysis

### Intelligence Sources

| Source | Type | Coverage |
|--------|------|----------|
| **VirusTotal** | Multi-AV | Files, URLs, domains, IPs |
| **AbuseIPDB** | IP Reputation | Abuse reports, confidence scoring |
| **Shodan** | Infrastructure | Open ports, vulnerabilities, SSL |
| **AlienVault OTX** | Threat Intel | Pulses, indicators, APT tracking |
| **URLhaus** | Malicious URLs | Malware distribution sites |
| **MalwareBazaar** | Malware Samples | Hash-based malware intel |
| **ThreatFox** | IOC Database | Fresh IOCs from security community |
| **FeodoTracker** | Botnet C2 | Feodo/Emotet infrastructure |
| **PhishTank** | Phishing | URL phishing verification |

### Output Capabilities

1. **Risk Assessment**
   - Risk level: HIGH / MEDIUM / LOW / MINIMAL
   - Numerical risk score (0-100)
   - Contributing risk factors

2. **KQL Hunting Queries**
   - Microsoft Defender EDR queries
   - Automated hunting across endpoints
   - Tailored to IOC type and risk level

3. **Actionable Recommendations**
   - Immediate response actions
   - Investigation steps
   - Mitigation strategies

## 📦 Installation

### Prerequisites
- Python 3.8+
- API keys for threat intelligence sources (see [Configuration](#configuration))

### Install Dependencies

```bash
# Clone repository
git clone https://github.com/YOUR_USERNAME/threat-intel-mcp.git
cd threat-intel-mcp

# Install requirements
pip install -r requirements.txt
```

## ⚙️ Configuration

### API Keys Setup

Create a `.env` file or set environment variables:

```bash
export VIRUSTOTAL_API_KEY="your_vt_api_key"
export ABUSEIPDB_API_KEY="your_abuseipdb_key"
export SHODAN_API_KEY="your_shodan_key"
export ALIENVAULT_OTX_API_KEY="your_otx_key"
export VIEWDNS_API_KEY="your_viewdns_key"  # Optional
```

### Getting API Keys

| Service | Free Tier | Get Key |
|---------|-----------|---------|
| VirusTotal | ✅ 500 req/day | [virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us) |
| AbuseIPDB | ✅ 1,000 req/day | [abuseipdb.com](https://www.abuseipdb.com/) |
| Shodan | ✅ 100 req/month | [account.shodan.io](https://account.shodan.io/) |
| AlienVault OTX | ✅ Unlimited | [otx.alienvault.com](https://otx.alienvault.com/) |

## 🎮 Usage

### Running the MCP Server

```bash
python server.py
```

### Claude Desktop Integration

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "threat-intelligence": {
      "command": "python",
      "args": ["/path/to/threat-intel-mcp/server.py"],
      "env": {
        "VIRUSTOTAL_API_KEY": "your_key_here",
        "ABUSEIPDB_API_KEY": "your_key_here",
        "SHODAN_API_KEY": "your_key_here",
        "ALIENVAULT_OTX_API_KEY": "your_key_here"
      }
    }
  }
}
```

### Example Queries

**Analyze an IP:**
```
Can you analyze this IP for threats: 192.168.1.1
```

**Check a domain:**
```
Is evil-domain.com malicious?
```

**Investigate a URL:**
```
Analyze this suspicious URL: http://malicious-site.com/payload.exe
```

**Hash lookup:**
```
Check this file hash: 44d88612fea8a8f36de82e1278abb02f
```

## 📊 Sample Output

```json
{
  "ioc": "192.0.2.1",
  "ioc_type": "ip",
  "risk_assessment": {
    "risk_level": "HIGH",
    "risk_score": 85,
    "factors": [
      "VirusTotal: 12/89 malicious",
      "AbuseIPDB: 92% confidence",
      "Shodan: 3 vulnerabilities",
      "AlienVault: 15 pulses"
    ]
  },
  "intelligence_sources": {
    "VirusTotal": {
      "malicious": 12,
      "suspicious": 3,
      "total_vendors": 89
    },
    "AbuseIPDB": {
      "abuse_confidence_score": 92,
      "total_reports": 156,
      "country": "CN"
    }
  },
  "kql_queries": [
    "DeviceNetworkEvents | where RemoteIP == \"192.0.2.1\"",
    "DeviceEvents | search \"192.0.2.1\" | summarize count() by DeviceName"
  ],
  "recommendations": [
    "⚠️ IMMEDIATE ACTION REQUIRED - IP flagged as HIGH RISK",
    "1. Block this IOC across all security controls",
    "2. Hunt for existing connections",
    "3. Isolate affected systems immediately"
  ]
}
```

## 🏗️ Architecture

```
┌─────────────────────────────────────────────┐
│           Claude Desktop / API              │
└──────────────────┬──────────────────────────┘
                   │ MCP Protocol
┌──────────────────▼──────────────────────────┐
│         Threat Intelligence Server          │
│  ┌─────────────────────────────────────┐   │
│  │   IOC Type Detection & Validation   │   │
│  └─────────────────┬───────────────────┘   │
│                    │                        │
│  ┌─────────────────▼───────────────────┐   │
│  │   Multi-Source Query Orchestrator   │   │
│  │   (Async, Concurrent, Rate-Limited) │   │
│  └─────────────────┬───────────────────┘   │
│                    │                        │
│  ┌─────────────────▼───────────────────┐   │
│  │      Risk Scoring Engine            │   │
│  │   (Multi-factor Analysis)           │   │
│  └─────────────────┬───────────────────┘   │
│                    │                        │
│  ┌─────────────────▼───────────────────┐   │
│  │   Recommendation Generator          │   │
│  │   (KQL Queries + Action Items)      │   │
│  └─────────────────────────────────────┘   │
└─────────────────────────────────────────────┘
```

## 🔒 Security Considerations

- **API Keys**: Never commit API keys to version control
- **Rate Limiting**: Built-in respect for API rate limits
- **Data Privacy**: No IOC data is stored or logged
- **Attribution**: All intelligence is attributed to source

## 🛠️ Development

### Project Structure

```
threat-intel-mcp/
├── server.py              # Main MCP server
├── requirements.txt       # Python dependencies
├── README.md             # This file
├── LICENSE               # MIT License
├── .gitignore            # Git ignore rules
├── config.yaml.example   # Config template
└── tests/                # Unit tests (coming soon)
```

### Running Tests

```bash
pytest tests/
```

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 Roadmap

- [ ] Rate limiting and caching
- [ ] Additional threat intel sources (Hybrid Analysis, Any.run)
- [ ] MITRE ATT&CK mapping
- [ ] PDF/HTML report generation
- [ ] Webhook notifications
- [ ] Historical tracking and trending
- [ ] Custom risk scoring profiles

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👤 Author

**Uğurcan Ateş**
- SOC Team Lead @ TAV Technologies
- Aviation Cybersecurity Specialist
- LinkedIn: [linkedin.com/in/ugurcanates](https://linkedin.com/in/ugurcanates)
- Medium: [@ugur.can.ates](https://medium.com/@ugur.can.ates)
- GitHub: [@ugurcanates](https://github.com/ugurcanates)

## 🙏 Acknowledgments

- [Model Context Protocol](https://modelcontextprotocol.io) by Anthropic
- All threat intelligence providers for their invaluable data
- Aviation security community for domain expertise

## ⚠️ Disclaimer

This tool is for **legitimate security research and defense purposes only**. Users are responsible for complying with all applicable laws and the terms of service of integrated threat intelligence platforms.

---

**Made with ❤️ for Aviation Cybersecurity**
