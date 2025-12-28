# Changelog

All notable changes to MCP For SOC Teams will be documented in this file.

## [2.2.0] - 2024-12-28

### Added
- **Multi-Platform Detection Rule Generation** - Ready-to-use detection rules for 5 platforms:
  - KQL (Microsoft Defender EDR) - Network, file, and process hunting queries
  - SPL (Splunk) - Firewall, proxy, and timeline analysis queries
  - SIGMA (Universal SIEM) - Platform-agnostic YAML rules
  - XQL (Cortex XDR) - Dataset-based endpoint and network queries
  - YARA (Malware Detection) - File hash and string matching rules

- **USOM Integration** - Turkish National Threat Intelligence
  - Automatic cross-check with USOM malicious URL/IP database
  - Scoring boost for USOM-listed threats (+25 threat, +15 impact)
  - Critical infrastructure protection for Turkish organizations

- **VirusTotal Community Intelligence**
  - Automatic extraction of security researcher comments
  - Community vote aggregation (positive/negative)
  - Threat actor attribution from expert analysts
  - Confidence scoring boost based on community validation
  - Top 10 most relevant comments displayed

- **Domain Entropy Analysis** - DNS Tunneling & DGA Detection
  - Shannon entropy calculation for subdomain randomness
  - Base32/Base64 encoding detection
  - Length analysis for tunnel detection
  - Confidence scoring (high/medium/low)
  - Automatic threat score adjustment

- **Malware Family Identification**
  - Auto-extraction from VirusTotal detections
  - Sandbox result parsing (Hybrid Analysis, ANY.RUN, Tria.ge, Threat.Zone)
  - Abuse.ch signature mapping
  - Family tagging in SIGMA and YARA rules

- **JARM/JA3 Known C2 Database**
  - Cobalt Strike fingerprints (multiple versions)
  - Metasploit default configurations
  - Sliver Go-based C2
  - Brute Ratel C4
  - Empire, Covenant, Mythic frameworks
  - Trickbot, Emotet JA3 hashes

### Changed
- Intelligence sources increased from 12+ to 17+
- Enhanced IOC scoring algorithm with community intelligence
- Improved confidence calculation with vote-based validation
- Updated startup banner with new feature list

### Technical Details
- New module: `detection_rules.py` - Multi-platform rule generators
- Enhanced: `c2_signatures.py` - Added JARM/JA3 databases
- New functions:
  - `query_virustotal_comments()` - VT community API
  - `query_usom_malicious_list()` - Turkish threat intel
  - `analyze_domain_entropy()` - DNS tunneling detection
  - `extract_malware_families()` - Cross-source family extraction
  - `generate_spl_queries()` - Splunk query generator
  - `generate_sigma_rules()` - SIGMA rule generator
  - `generate_xql_queries()` - Cortex XDR query generator
  - `generate_yara_rules()` - YARA rule generator

---

## [2.1.0] - 2024-12-27

### Added
- **C2 Infrastructure Detection**
  - 3 C2 tracker repositories integration:
    - Daily Dose of Malware (Titokhan)
    - JMousqueton C2-Tracker
    - C2Live (YoNixNeXRo)
  - 80+ C2/Malware/Botnet keyword signatures
  - Enhanced Shodan C2 detection with confidence scoring
  - Automatic C2 scoring escalation (+30 threat, +20 impact)

- **Malware Classification**
  - C2 Frameworks (23): Cobalt Strike, Sliver, Havoc, Empire, etc.
  - Information Stealers (27): Lumma, Vidar, Mystic, etc.
  - Remote Access Trojans (24): Quasar RAT, AsyncRAT, DcRat, etc.
  - Malware Loaders (4): Godzilla, Jinx, Netpune, Bumblebee
  - Attack Tools (11): XMRig, GoPhish, BeEF, etc.
  - Botnets (8): BlackNET, Kaiji, MooBot, Mozi, etc.

- **Shodan C2 Detection**
  - Keyword matching in banners/products/services
  - Pattern-based detection with specific queries
  - Category identification (C2 Framework, Stealer, RAT, etc.)
  - High/Medium/Low confidence scoring

### Changed
- Scoring algorithm updated with C2 tracker bonuses
- Intelligence sources increased to 15+

---

## [2.0.0] - 2024-12-26

### Added
- **Normalized IOC Scoring System (0-100)**
  - Industry-standard multi-factor scoring:
    - Threat Score (40%): Malicious detections
    - Confidence Score (30%): Source count & consensus
    - Impact Score (20%): Vulnerabilities, tactics, pulses
    - Freshness Score (10%): Analysis recency
  - Severity classification: CRITICAL/HIGH/MEDIUM/LOW/MINIMAL
  - Priority levels: P1-P5

- **5 Sandbox Platform Integrations**
  - Hybrid Analysis - Windows/Linux/Android analysis with MITRE mapping
  - ANY.RUN - Interactive sandbox with real-time analysis
  - Tria.ge (Hatching) - Automated analysis with config extraction
  - Threat.Zone - Behavioral analysis with YARA matching
  - VirusTotal File Upload - Added file submission capability

- **MITRE ATT&CK Mapping**
  - Automatic tactic/technique extraction
  - Source attribution (Hybrid Analysis, ANY.RUN, Tria.ge)
  - Signature-to-tactic mapping

- **Network IOC Extraction**
  - IP addresses from sandbox traffic
  - Domains from DNS queries
  - URLs from HTTP connections
  - Batch KQL query generation for related IOCs

- **Enhanced KQL Query Generation**
  - IOC-type specific queries
  - Severity-adjusted hunt queries (30-day for CRITICAL)
  - Network IOC correlation queries
  - Process command line analysis

- **Severity-Based Recommendations**
  - CRITICAL (P1): Immediate blocking, isolation, forensics, IR playbook
  - HIGH (P2): Urgent investigation, risk assessment, containment
  - MEDIUM/LOW: Watchlist monitoring, documentation

### Changed
- Complete server.py rewrite (1200+ lines)
- Intelligence sources increased to 12+
- Enhanced VirusTotal integration with file upload

---

## [1.0.0] - 2024-12-20

### Added
- Initial release
- 9 core threat intelligence sources:
  - VirusTotal
  - AbuseIPDB
  - Shodan
  - AlienVault OTX
  - Abuse.ch (URLhaus, MalwareBazaar, ThreatFox)
- Basic IOC detection (IP, domain, URL, hash)
- Risk assessment scoring
- KQL query generation for Microsoft Defender
- MCP protocol integration
- Async query execution

---

## Upcoming Features (Roadmap)

### v2.3 (Planned)
- [ ] Local C2 tracker cache (reduce GitHub API calls)
- [ ] Historical IOC tracking (first seen/last seen)
- [ ] Automated MISP integration
- [ ] Custom playbook templates
- [ ] Enhanced JARM active scanning
- [ ] PDF report generation

### v3.0 (Future)
- [ ] Machine learning anomaly detection
- [ ] Automated threat hunting workflows
- [ ] Integration with SOAR platforms
- [ ] Real-time threat feed subscriptions
- [ ] Advanced correlation engine
- [ ] Multi-tenant support
