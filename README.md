# 🛡️ Multi-Source Threat Intelligence MCP Server v2.2

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![MCP](https://img.shields.io/badge/MCP-Compatible-green.svg)](https://modelcontextprotocol.io)
[![Version](https://img.shields.io/badge/version-2.2-brightgreen.svg)](https://github.com/ugurrates/MCP-For-SOC)

**Aviation-focused threat intelligence platform** with **multi-platform detection rule generation**, **C2 infrastructure detection**, **sandbox analysis**, **normalized IOC scoring**, and **MITRE ATT&CK mapping**.

## 🚀 What's New in v2.2

### 🆕 Multi-Platform Detection Rule Generation

**Ready-to-Use Detection Rules for 5 Platforms:**
1. **KQL** (Microsoft Defender EDR) - Hunt queries for endpoints and network
2. **SPL** (Splunk) - Search queries for SIEM analysis
3. **SIGMA** (Universal SIEM) - Platform-agnostic detection rules
4. **XQL** (Cortex XDR) - Palo Alto Cortex hunting queries
5. **YARA** (Malware Detection) - File and memory scanning rules

**Usage:** Copy/paste generated rules directly into your security tools - no modification needed!

## 🚀 What's New in v2.1

### 🆕 C2 Infrastructure Detection

**1. C2 Tracker Integration (3 Sources)**
- 🔍 **Daily Dose of Malware** - Real-time IOC tracking
- 🎯 **JMousqueton C2-Tracker** - Active C2 server database
- ⚡ **C2Live** - Live C2 IP tracking
- Automatic cross-referencing with 3 major C2 tracker repositories

**2. Malware/C2 Signature Detection (80+ Keywords)**
- **C2 Frameworks** (23): Cobalt Strike, Sliver, Metasploit, Covenant, Mythic, Brute Ratel C4, etc.
- **Malware Families** (50+): Stealers, RATs, Trojans, Loaders
  - Stealers: Lumma, Vidar, Mystic, Gotham, Meduza, RisePro, etc.
  - RATs: AsyncRAT, Quasar, njRAT, VenomRAT, DcRat, etc.
- **Attack Tools**: XMRig, GoPhish, BeEF, EvilGinx, etc.
- **Botnets**: 7777, Mozi, Kaiji, BlackNET, etc.

**3. Enhanced Shodan C2 Detection**
- Automatic keyword matching in Shodan banners
- Pattern-based C2 framework identification
- Confidence scoring (high/medium/low)
- Identifies 23+ C2 frameworks in infrastructure

**4. Advanced C2 Scoring**
- Confirmed C2 infrastructure: +30 threat score, +20 impact score
- High confidence detection: +25 threat score, +15 impact score
- Automatic severity escalation for C2 indicators

### ✨ Previous Features (v2.0)

**1. Normalized IOC Scoring (0-100)**
- Industry-standard scoring framework
- Multi-factor analysis: Threat (40%) + Confidence (30%) + Impact (20%) + Freshness (10%)
- Automated severity classification: CRITICAL / HIGH / MEDIUM / LOW / MINIMAL

**2. Sandbox Integration (5 Platforms)**
- 🔬 **Hybrid Analysis** - Comprehensive malware analysis
- 🎮 **ANY.RUN** - Interactive sandbox
- 🔍 **Tria.ge** - Automated malware detection
- ⚡ **Threat.Zone** - Behavioral analysis + IOC extraction
- 📤 **VirusTotal** - File upload support (NEW!)

**3. MITRE ATT&CK Mapping**
- Automatic tactic/technique extraction from sandbox results
- Maps behaviors to ATT&CK framework
- Identifies attack patterns

**4. Network IOC Extraction**
- Extracts IPs, domains, URLs from sandbox analysis
- Generates additional hunting queries for related IOCs
- Comprehensive network behavior analysis

## 📊 Intelligence Sources (15+)

| Source | Type | Free Tier | Coverage |
|--------|------|-----------|----------|
| **C2-Trackers (3)** | **C2 Infrastructure** | **✅ Unlimited** | **Active C2 servers, IOCs** |
| **VirusTotal** | Multi-AV + Sandbox | ✅ 500/day | Files, URLs, domains, IPs |
| **Hybrid Analysis** | Sandbox | ✅ 100/month | Windows/Linux/Android malware |
| **ANY.RUN** | Interactive Sandbox | ✅ Public submissions | Real-time analysis |
| **Tria.ge** | Automated Sandbox | ✅ 20/day | Family detection, config extraction |
| **Threat.Zone** | Behavioral Analysis | ✅ Available | IOC extraction, YARA matching |
| **AbuseIPDB** | IP Reputation | ✅ 1000/day | Abuse reports, confidence scoring |
| **Shodan** | Infrastructure + C2 | ✅ 100/month | Ports, vulns, C2 detection |
| **AlienVault OTX** | Threat Intel | ✅ Unlimited | Pulses, indicators, APT tracking |
| **URLhaus** | Malicious URLs | ✅ Unlimited | Malware distribution sites |
| **MalwareBazaar** | Malware Samples | ✅ Unlimited | Hash-based malware intel |
| **ThreatFox** | IOC Database | ✅ Unlimited | Fresh IOCs |
| **FeodoTracker** | Botnet C2 | ✅ Unlimited | Feodo/Emotet infrastructure |

## 🎯 Key Capabilities

### Supported IOC Types
- ✅ **File Hashes**: MD5, SHA1, SHA256
- ✅ **IP Addresses**: IPv4 with geolocation, reputation, vulnerabilities
- ✅ **Domains**: DNS, WHOIS, SSL certificate analysis
- ✅ **URLs**: Link reputation, phishing detection

### Analysis Output

**1. Normalized IOC Score**
```json
{
  "final_score": 87.5,
  "severity": "HIGH",
  "priority": "P2",
  "breakdown": {
    "threat_score": 35.2,
    "confidence_score": 30.0,
    "impact_score": 15.3,
    "freshness_score": 10.0
  }
}
```

**2. MITRE ATT&CK Mapping**
- Automatic tactic/technique identification
- Maps to ATT&CK framework (TA####, T####)
- Source attribution

**3. Network IOCs**
- Extracted IPs, domains, URLs from sandbox
- Total IOC count
- Ready for additional hunting

**4. KQL Hunting Queries**
- Microsoft Defender EDR queries
- Automated based on IOC type
- Severity-adjusted complexity
- Includes queries for related IOCs

**5. Actionable Recommendations**
- Severity-based response playbook
- Immediate actions for CRITICAL/HIGH
- Investigation steps
- Containment strategies

## 📦 Installation

### Prerequisites
- Python 3.8+
- API keys for threat intelligence sources

### Quick Start

```bash
# Clone repository
git clone https://github.com/ugurrates/MCP-For-SOC.git
cd MCP-For-SOC

# Install dependencies
pip install -r requirements.txt

# Configure API keys (see Configuration section)
cp config.yaml.example config.yaml
# Edit config.yaml with your API keys

# Run server
python server.py
```

## ⚙️ Configuration

### API Keys Setup

Create `.env` file or set environment variables:

```bash
# Core Sources
export VIRUSTOTAL_API_KEY="your_key"
export ABUSEIPDB_API_KEY="your_key"
export SHODAN_API_KEY="your_key"
export ALIENVAULT_OTX_API_KEY="your_key"

# Sandbox Platforms (v2.0)
export HYBRID_ANALYSIS_API_KEY="your_key"
export ANYRUN_API_KEY="your_key"
export TRIAGE_API_KEY="your_key"
export THREAT_ZONE_API_KEY="your_key"
```

### Getting Free API Keys

| Service | Signup Link | Free Tier |
|---------|-------------|-----------|
| VirusTotal | [virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us) | 500 requests/day |
| AbuseIPDB | [abuseipdb.com](https://www.abuseipdb.com/) | 1,000/day |
| Shodan | [account.shodan.io](https://account.shodan.io/) | 100/month |
| AlienVault OTX | [otx.alienvault.com](https://otx.alienvault.com/) | Unlimited |
| Hybrid Analysis | [hybrid-analysis.com/apikeys/info](https://www.hybrid-analysis.com/apikeys/info) | 100/month |
| ANY.RUN | [any.run/api-documentation](https://any.run/api-documentation/) | Public submissions |
| Tria.ge | [tria.ge/account](https://tria.ge/account) | 20/day |
| Threat.Zone | [app.threat.zone](https://app.threat.zone/public-api/docs) | Free tier available |

## 🎮 Usage

### Claude Desktop Integration

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "threat-intelligence-v2": {
      "command": "python",
      "args": ["/path/to/MCP-For-SOC/server.py"],
      "env": {
        "VIRUSTOTAL_API_KEY": "your_key",
        "HYBRID_ANALYSIS_API_KEY": "your_key",
        "ANYRUN_API_KEY": "your_key",
        "TRIAGE_API_KEY": "your_key",
        "THREAT_ZONE_API_KEY": "your_key"
      }
    }
  }
}
```

### Example Queries

**Analyze a suspicious file hash:**
```
Analyze this hash for threats: 44d88612fea8a8f36de82e1278abb02f
```

**Check a potentially malicious IP:**
```
Is 192.0.2.1 malicious? Run full threat intelligence.
```

**Investigate a phishing domain:**
```
Analyze suspicious-domain.com for threats
```

## 📈 Sample Output

```json
{
  "ioc": "44d88612fea8a8f36de82e1278abb02f",
  "ioc_type": "hash_md5",
  "normalized_score": {
    "final_score": 92.3,
    "severity": "CRITICAL",
    "priority": "P1",
    "breakdown": {
      "threat_score": 38.5,
      "confidence_score": 30.0,
      "impact_score": 18.8,
      "freshness_score": 10.0
    },
    "contributing_factors": [
      "VirusTotal: 45/70 engines detected malware (64%)",
      "Hybrid Analysis: Threat score 95/100",
      "Strong consensus across multiple sources",
      "MITRE ATT&CK: 8 tactics identified"
    ]
  },
  "intelligence_sources": {
    "VirusTotal": { "malicious": 45, "total_vendors": 70 },
    "Hybrid-Analysis": { "threat_score": 95, "verdict": "malicious" },
    "ANY.RUN": { "verdict": "malicious", "malware_families": ["emotet"] },
    "Tria.ge": { "score": 9, "family": "Emotet" }
  },
  "network_iocs": {
    "ips": ["198.51.100.1", "203.0.113.5"],
    "domains": ["malicious-c2.com"],
    "total_iocs": 3
  },
  "mitre_attck": [
    {
      "tactic": "execution",
      "technique": "PowerShell",
      "technique_id": "T1059.001",
      "source": "Hybrid Analysis"
    }
  ],
  "kql_hunting_queries": [
    "// Hunt for file by hash\nDeviceFileEvents\n| where MD5 == \"44d88612fea8a8f36de82e1278abb02f\"",
    "// Hunt for related malicious IPs\nDeviceNetworkEvents\n| where RemoteIP in (\"198.51.100.1\", \"203.0.113.5\")"
  ],
  "recommendations": [
    "🚨 CRITICAL THREAT DETECTED - Immediate action required",
    "1. BLOCK hash across all security controls",
    "2. HUNT for existing activity using KQL queries",
    "3. ISOLATE affected systems immediately"
  ]
}
```

## 🏗️ Architecture

```
┌─────────────────────────────────────────────┐
│         Claude Desktop / API Client         │
└──────────────────┬──────────────────────────┘
                   │ MCP Protocol
┌──────────────────▼──────────────────────────┐
│    Threat Intelligence MCP Server v2.0      │
│  ┌─────────────────────────────────────┐   │
│  │   IOC Detection & Validation        │   │
│  └─────────────────┬───────────────────┘   │
│                    │                        │
│  ┌─────────────────▼───────────────────┐   │
│  │   Multi-Source Query Orchestrator   │   │
│  │   12+ Sources (Concurrent Async)    │   │
│  └─────────────────┬───────────────────┘   │
│                    │                        │
│  ┌─────────────────▼───────────────────┐   │
│  │   Sandbox Analysis Integration      │   │ NEW!
│  │   (Hybrid, ANY.RUN, Triage, etc.)   │   │
│  └─────────────────┬───────────────────┘   │
│                    │                        │
│  ┌─────────────────▼───────────────────┐   │
│  │   Network IOC Extraction            │   │ NEW!
│  └─────────────────┬───────────────────┘   │
│                    │                        │
│  ┌─────────────────▼───────────────────┐   │
│  │   MITRE ATT&CK Mapping              │   │ NEW!
│  └─────────────────┬───────────────────┘   │
│                    │                        │
│  ┌─────────────────▼───────────────────┐   │
│  │   Normalized IOC Scoring Engine     │   │ NEW!
│  │   (0-100 Industry Standard)         │   │
│  └─────────────────┬───────────────────┘   │
│                    │                        │
│  ┌─────────────────▼───────────────────┐   │
│  │   KQL Query + Recommendations       │   │
│  └─────────────────────────────────────┘   │
└─────────────────────────────────────────────┘
```

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open Pull Request

## 📝 Changelog

### v2.2 (Current)
- ✅ **Multi-Platform Detection Rules**
  - KQL (Microsoft Defender EDR)
  - SPL (Splunk)
  - SIGMA (Universal SIEM)
  - XQL (Cortex XDR)
  - YARA (Malware Detection)
- ✅ **USOM Integration** (Turkish National Threat Intel)
- ✅ **VirusTotal Community Intelligence** (Researcher comments & votes)
- ✅ **Domain Entropy Analysis** (DNS Tunneling/DGA Detection)
- ✅ **Malware Family Identification** (Auto-extraction from sandbox)
- ✅ **JARM/JA3 Known C2 Database** (Cobalt Strike, Metasploit, Sliver, etc.)
- ✅ Enhanced threat scoring with USOM, community insights, and entropy analysis

### v2.1
- ✅ C2 Infrastructure Detection
  - 3 C2 tracker repositories integration
  - 80+ C2/Malware/Botnet keyword signatures
  - Enhanced Shodan C2 detection
  - Automatic C2 scoring escalation
- ✅ Malware family identification from Shodan banners
- ✅ Confidence-based C2 detection (high/medium/low)

### v2.0
- ✅ Normalized IOC scoring system (0-100)
- ✅ 5 sandbox platform integrations
- ✅ MITRE ATT&CK mapping
- ✅ Network IOC extraction
- ✅ Enhanced KQL query generation
- ✅ Severity-based recommendations

### v1.0
- Initial release
- 9 threat intelligence sources
- Basic risk assessment
- KQL query generation

## 📄 License

MIT License - see [LICENSE](LICENSE) file

## 👤 Author

**Ugur Ates**
- SOC Team Lead @ TAV Technologies
- Aviation Cybersecurity Specialist
- LinkedIn: [linkedin.com/in/ugurcanates](https://linkedin.com/in/ugurcanates)
- Medium: [@ugur.can.ates](https://medium.com/@ugur.can.ates)
- GitHub: [@ugurrates](https://github.com/ugurrates)

## ⚠️ Disclaimer

For **legitimate security research and defense purposes only**. Users are responsible for complying with all applicable laws and ToS of intelligence platforms.

---

**Made with ❤️ for Aviation Cybersecurity**

**MCP For SOC Teams** | Empowering security operations with automated threat intelligence
