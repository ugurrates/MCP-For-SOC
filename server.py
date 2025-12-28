#!/usr/bin/env python3
"""
Multi-Source Threat Intelligence MCP Server
Aviation-focused threat intelligence platform integrating 9+ sources
Author: Uğurcan Ateş
"""

import asyncio
import hashlib
import json
import logging
import re
from typing import Dict, List, Optional
from urllib.parse import urlparse

import aiohttp
from mcp.server import Server
from mcp.types import Resource, Tool, TextContent

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# API Keys - Should be set via environment variables
API_KEYS = {
    'VIRUSTOTAL_API_KEY': '',
    'ABUSEIPDB_API_KEY': '',
    'SHODAN_API_KEY': '',
    'VIEWDNS_API_KEY': '',
    'ALIENVAULT_OTX_API_KEY': ''
}

# MCP Server instance
server = Server("threat-intelligence-mcp")


def detect_ioc_type(ioc: str) -> str:
    """Detect IOC type: hash, ip, domain, or url"""
    ioc = ioc.strip()
    
    # Hash detection (MD5, SHA1, SHA256)
    if re.match(r'^[a-fA-F0-9]{32}$', ioc):
        return 'hash_md5'
    elif re.match(r'^[a-fA-F0-9]{40}$', ioc):
        return 'hash_sha1'
    elif re.match(r'^[a-fA-F0-9]{64}$', ioc):
        return 'hash_sha256'
    
    # URL detection
    if ioc.startswith(('http://', 'https://', 'ftp://')):
        return 'url'
    
    # IP detection
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ioc):
        return 'ip'
    
    # Domain detection
    if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$', ioc):
        return 'domain'
    
    return 'unknown'


def extract_domain_from_url(url: str) -> str:
    """Extract domain from URL"""
    try:
        parsed = urlparse(url)
        return parsed.netloc or parsed.path
    except:
        return url


async def query_virustotal(session: aiohttp.ClientSession, ioc: str, ioc_type: str) -> Dict:
    """Query VirusTotal API"""
    if not API_KEYS.get('VIRUSTOTAL_API_KEY'):
        return {"error": "VirusTotal API key not configured"}
    
    headers = {'x-apikey': API_KEYS['VIRUSTOTAL_API_KEY']}
    
    try:
        if ioc_type == 'url':
            # URL scan
            url_id = hashlib.sha256(ioc.encode()).hexdigest()
            endpoint = f'https://www.virustotal.com/api/v3/urls/{url_id}'
        elif ioc_type == 'domain':
            endpoint = f'https://www.virustotal.com/api/v3/domains/{ioc}'
        elif ioc_type == 'ip':
            endpoint = f'https://www.virustotal.com/api/v3/ip_addresses/{ioc}'
        elif 'hash' in ioc_type:
            endpoint = f'https://www.virustotal.com/api/v3/files/{ioc}'
        else:
            return {"error": "Unsupported IOC type"}
        
        async with session.get(endpoint, headers=headers, timeout=aiohttp.ClientTimeout(total=30)) as response:
            if response.status == 404:
                return {"status": "not_found", "message": "IOC not found in VirusTotal"}
            elif response.status == 429:
                return {"error": "Rate limit exceeded"}
            elif response.status != 200:
                return {"error": f"API error: {response.status}"}
            
            data = await response.json()
            
            if 'data' in data and 'attributes' in data['data']:
                attrs = data['data']['attributes']
                stats = attrs.get('last_analysis_stats', {})
                
                return {
                    "source": "VirusTotal",
                    "malicious": stats.get('malicious', 0),
                    "suspicious": stats.get('suspicious', 0),
                    "harmless": stats.get('harmless', 0),
                    "undetected": stats.get('undetected', 0),
                    "total_vendors": sum(stats.values()) if stats else 0,
                    "reputation": attrs.get('reputation', 0),
                    "last_analysis_date": attrs.get('last_analysis_date', 'N/A')
                }
            
            return data
            
    except Exception as e:
        logger.error(f"VirusTotal query error: {e}")
        return {"error": str(e)}


async def query_abuseipdb(session: aiohttp.ClientSession, ip: str) -> Dict:
    """Query AbuseIPDB API"""
    if not API_KEYS.get('ABUSEIPDB_API_KEY'):
        return {"error": "AbuseIPDB API key not configured"}
    
    headers = {
        'Key': API_KEYS['ABUSEIPDB_API_KEY'],
        'Accept': 'application/json'
    }
    
    params = {
        'ipAddress': ip,
        'maxAgeInDays': 90,
        'verbose': ''
    }
    
    try:
        async with session.get('https://api.abuseipdb.com/api/v2/check',
                             headers=headers, params=params,
                             timeout=aiohttp.ClientTimeout(total=30)) as response:
            if response.status == 429:
                return {"error": "Rate limit exceeded"}
            elif response.status != 200:
                return {"error": f"API error: {response.status}"}
            
            data = await response.json()
            
            if 'data' in data:
                info = data['data']
                return {
                    "source": "AbuseIPDB",
                    "abuse_confidence_score": info.get('abuseConfidenceScore', 0),
                    "total_reports": info.get('totalReports', 0),
                    "country": info.get('countryCode', 'N/A'),
                    "isp": info.get('isp', 'N/A'),
                    "usage_type": info.get('usageType', 'N/A'),
                    "is_whitelisted": info.get('isWhitelisted', False)
                }
            
            return data
            
    except Exception as e:
        logger.error(f"AbuseIPDB query error: {e}")
        return {"error": str(e)}


async def query_shodan(session: aiohttp.ClientSession, ip: str) -> Dict:
    """Query Shodan API"""
    if not API_KEYS.get('SHODAN_API_KEY'):
        return {"error": "Shodan API key not configured"}
    
    try:
        url = f'https://api.shodan.io/shodan/host/{ip}?key={API_KEYS["SHODAN_API_KEY"]}'
        
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as response:
            if response.status == 404:
                return {"status": "not_found", "message": "IP not found in Shodan"}
            elif response.status == 401:
                return {"error": "Invalid API key"}
            elif response.status != 200:
                return {"error": f"API error: {response.status}"}
            
            data = await response.json()
            
            return {
                "source": "Shodan",
                "ip": data.get('ip_str', ip),
                "country": data.get('country_name', 'N/A'),
                "organization": data.get('org', 'N/A'),
                "asn": data.get('asn', 'N/A'),
                "ports": data.get('ports', []),
                "vulns": list(data.get('vulns', [])),
                "last_update": data.get('last_update', 'N/A')
            }
            
    except Exception as e:
        logger.error(f"Shodan query error: {e}")
        return {"error": str(e)}


async def query_alienvault_otx(session: aiohttp.ClientSession, ioc: str, ioc_type: str) -> Dict:
    """Query AlienVault OTX API"""
    if not API_KEYS.get('ALIENVAULT_OTX_API_KEY'):
        return {"error": "AlienVault OTX API key not configured"}
    
    headers = {'X-OTX-API-KEY': API_KEYS['ALIENVAULT_OTX_API_KEY']}
    
    try:
        if ioc_type == 'ip':
            endpoint = f'https://otx.alienvault.com/api/v1/indicators/IPv4/{ioc}/general'
        elif ioc_type == 'domain':
            endpoint = f'https://otx.alienvault.com/api/v1/indicators/domain/{ioc}/general'
        elif ioc_type == 'url':
            endpoint = f'https://otx.alienvault.com/api/v1/indicators/url/{ioc}/general'
        elif 'hash' in ioc_type:
            endpoint = f'https://otx.alienvault.com/api/v1/indicators/file/{ioc}/general'
        else:
            return {"error": "Unsupported IOC type"}
        
        async with session.get(endpoint, headers=headers, timeout=aiohttp.ClientTimeout(total=30)) as response:
            if response.status == 404:
                return {"status": "not_found", "message": "IOC not found in AlienVault OTX"}
            elif response.status != 200:
                return {"error": f"API error: {response.status}"}
            
            data = await response.json()
            
            return {
                "source": "AlienVault OTX",
                "pulse_count": data.get('pulse_info', {}).get('count', 0),
                "pulses": [p.get('name') for p in data.get('pulse_info', {}).get('pulses', [])[:5]],
                "indicator": ioc,
                "type": ioc_type
            }
            
    except Exception as e:
        logger.error(f"AlienVault OTX query error: {e}")
        return {"error": str(e)}


async def query_abuse_ch(session: aiohttp.ClientSession, ioc: str, ioc_type: str) -> Dict:
    """Query Abuse.ch (URLhaus, MalwareBazaar, ThreatFox)"""
    results = {}
    
    try:
        # URLhaus
        if ioc_type in ['url', 'domain']:
            try:
                data = {'url': ioc} if ioc_type == 'url' else {'host': ioc}
                async with session.post('https://urlhaus-api.abuse.ch/v1/url/',
                                      data=data,
                                      timeout=aiohttp.ClientTimeout(total=30)) as response:
                    if response.status == 200:
                        urlhaus_data = await response.json()
                        if urlhaus_data.get('query_status') == 'ok':
                            results['URLhaus'] = {
                                "status": urlhaus_data.get('threat', 'N/A'),
                                "date_added": urlhaus_data.get('date_added', 'N/A'),
                                "tags": urlhaus_data.get('tags', [])
                            }
            except:
                pass
        
        # MalwareBazaar (for hashes)
        if 'hash' in ioc_type:
            try:
                data = {'query': 'get_info', 'hash': ioc}
                async with session.post('https://mb-api.abuse.ch/api/v1/',
                                      data=data,
                                      timeout=aiohttp.ClientTimeout(total=30)) as response:
                    if response.status == 200:
                        mb_data = await response.json()
                        if mb_data.get('query_status') == 'ok':
                            results['MalwareBazaar'] = {
                                "signature": mb_data['data'][0].get('signature', 'N/A'),
                                "file_type": mb_data['data'][0].get('file_type', 'N/A'),
                                "tags": mb_data['data'][0].get('tags', [])
                            }
            except:
                pass
        
        return {"source": "Abuse.ch", "results": results} if results else {"status": "not_found"}
        
    except Exception as e:
        logger.error(f"Abuse.ch query error: {e}")
        return {"error": str(e)}


def calculate_risk_score(results: Dict) -> tuple:
    """Calculate risk score from all sources"""
    score = 0
    factors = []
    
    # VirusTotal scoring
    if 'VirusTotal' in results and 'malicious' in results['VirusTotal']:
        vt = results['VirusTotal']
        if vt['malicious'] > 5:
            score += 40
            factors.append(f"VirusTotal: {vt['malicious']}/{vt['total_vendors']} malicious")
        elif vt['malicious'] > 0:
            score += 20
            factors.append(f"VirusTotal: {vt['malicious']} detections")
    
    # AbuseIPDB scoring
    if 'AbuseIPDB' in results and 'abuse_confidence_score' in results['AbuseIPDB']:
        abuse_score = results['AbuseIPDB']['abuse_confidence_score']
        if abuse_score > 75:
            score += 30
            factors.append(f"AbuseIPDB: {abuse_score}% confidence")
        elif abuse_score > 50:
            score += 15
            factors.append(f"AbuseIPDB: {abuse_score}% confidence")
    
    # Shodan vulnerabilities
    if 'Shodan' in results and 'vulns' in results['Shodan']:
        vulns = len(results['Shodan']['vulns'])
        if vulns > 0:
            score += min(vulns * 5, 20)
            factors.append(f"Shodan: {vulns} vulnerabilities")
    
    # AlienVault OTX
    if 'AlienVault OTX' in results and 'pulse_count' in results['AlienVault OTX']:
        pulse_count = results['AlienVault OTX']['pulse_count']
        if pulse_count > 10:
            score += 20
            factors.append(f"AlienVault: {pulse_count} pulses")
        elif pulse_count > 0:
            score += 10
            factors.append(f"AlienVault: {pulse_count} pulses")
    
    # Abuse.ch
    if 'Abuse.ch' in results and results['Abuse.ch'].get('results'):
        score += 25
        factors.append("Found in Abuse.ch databases")
    
    # Determine risk level
    if score >= 70:
        risk_level = "HIGH"
    elif score >= 40:
        risk_level = "MEDIUM"
    elif score >= 20:
        risk_level = "LOW"
    else:
        risk_level = "MINIMAL"
    
    return risk_level, score, factors


def generate_kql_queries(ioc: str, ioc_type: str, risk_level: str) -> List[str]:
    """Generate Microsoft Defender EDR KQL queries"""
    queries = []
    
    if ioc_type == 'ip':
        queries.extend([
            f'DeviceNetworkEvents | where RemoteIP == "{ioc}" | project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort',
            f'DeviceNetworkEvents | where RemoteIP == "{ioc}" and ActionType == "ConnectionSuccess" | summarize count() by DeviceName',
            f'DeviceProcessEvents | where ProcessCommandLine has "{ioc}"'
        ])
    elif ioc_type == 'domain':
        queries.extend([
            f'DeviceNetworkEvents | where RemoteUrl has "{ioc}" | project Timestamp, DeviceName, RemoteUrl, InitiatingProcessFileName',
            f'DeviceEvents | where AdditionalFields has "{ioc}"',
            f'EmailUrlInfo | where Url has "{ioc}" | project Timestamp, SenderFromAddress, RecipientEmailAddress'
        ])
    elif ioc_type == 'url':
        domain = extract_domain_from_url(ioc)
        queries.extend([
            f'DeviceNetworkEvents | where RemoteUrl == "{ioc}" | project Timestamp, DeviceName, ActionType',
            f'EmailUrlInfo | where Url == "{ioc}"',
            f'DeviceNetworkEvents | where RemoteUrl has "{domain}"'
        ])
    elif 'hash' in ioc_type:
        queries.extend([
            f'DeviceFileEvents | where {ioc_type.split("_")[1].upper()} == "{ioc}" | project Timestamp, DeviceName, FileName, FolderPath',
            f'DeviceProcessEvents | where {ioc_type.split("_")[1].upper()} == "{ioc}"',
            f'DeviceImageLoadEvents | where {ioc_type.split("_")[1].upper()} == "{ioc}"'
        ])
    
    if risk_level == "HIGH":
        queries.append(f'DeviceEvents | where Timestamp > ago(30d) | search "{ioc}" | summarize count() by DeviceName, ActionType')
    
    return queries


def generate_recommendations(ioc: str, ioc_type: str, risk_level: str, results: Dict) -> List[str]:
    """Generate actionable recommendations"""
    recommendations = []
    
    if risk_level == "HIGH":
        recommendations.extend([
            f"⚠️ IMMEDIATE ACTION REQUIRED - {ioc_type.upper()} flagged as HIGH RISK",
            "1. Block this IOC across all security controls (Firewall, EDR, Proxy)",
            "2. Hunt for existing connections/communications with this IOC",
            "3. Isolate affected systems immediately",
            "4. Conduct forensic analysis on compromised endpoints"
        ])
    elif risk_level == "MEDIUM":
        recommendations.extend([
            f"🔍 INVESTIGATION RECOMMENDED - {ioc_type.upper()} shows suspicious indicators",
            "1. Monitor traffic to/from this IOC",
            "2. Review recent access logs",
            "3. Consider temporary blocking pending investigation"
        ])
    elif risk_level == "LOW":
        recommendations.extend([
            f"📊 LOW RISK - {ioc_type.upper()} has minor suspicious indicators",
            "1. Add to watchlist for monitoring",
            "2. Document findings in threat intelligence platform"
        ])
    else:
        recommendations.extend([
            f"✓ MINIMAL RISK - {ioc_type.upper()} appears benign",
            "1. No immediate action required",
            "2. Continue standard monitoring"
        ])
    
    return recommendations


@server.list_tools()
async def list_tools() -> List[Tool]:
    """List available MCP tools"""
    return [
        Tool(
            name="analyze_threat",
            description="Comprehensive 3-phase threat intelligence analysis across 9+ sources. "
                       "Supports IPs, domains, URLs, and file hashes. "
                       "Returns risk assessment, KQL queries, and actionable recommendations.",
            inputSchema={
                "type": "object",
                "properties": {
                    "ioc": {
                        "type": "string",
                        "description": "Indicator of Compromise (IP, domain, URL, or hash)"
                    }
                },
                "required": ["ioc"]
            }
        )
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> List[TextContent]:
    """Handle tool calls"""
    if name == "analyze_threat":
        ioc = arguments.get("ioc", "").strip()
        
        if not ioc:
            return [TextContent(
                type="text",
                text="Error: No IOC provided"
            )]
        
        # Detect IOC type
        ioc_type = detect_ioc_type(ioc)
        
        if ioc_type == 'unknown':
            return [TextContent(
                type="text",
                text=f"Error: Unable to detect IOC type for: {ioc}"
            )]
        
        logger.info(f"Analyzing {ioc_type}: {ioc}")
        
        # Phase 1: Multi-source threat intelligence gathering
        results = {}
        
        async with aiohttp.ClientSession() as session:
            tasks = []
            
            # VirusTotal
            tasks.append(('VirusTotal', query_virustotal(session, ioc, ioc_type)))
            
            # IP-specific sources
            if ioc_type == 'ip':
                tasks.append(('AbuseIPDB', query_abuseipdb(session, ioc)))
                tasks.append(('Shodan', query_shodan(session, ioc)))
            
            # AlienVault OTX (all types)
            tasks.append(('AlienVault OTX', query_alienvault_otx(session, ioc, ioc_type)))
            
            # Abuse.ch
            tasks.append(('Abuse.ch', query_abuse_ch(session, ioc, ioc_type)))
            
            # Execute all queries concurrently
            for source_name, task in tasks:
                try:
                    result = await task
                    if result and 'error' not in result:
                        results[source_name] = result
                except Exception as e:
                    logger.error(f"{source_name} query failed: {e}")
        
        # Phase 2: Risk assessment
        risk_level, risk_score, risk_factors = calculate_risk_score(results)
        
        # Phase 3: Generate recommendations and KQL queries
        kql_queries = generate_kql_queries(ioc, ioc_type, risk_level)
        recommendations = generate_recommendations(ioc, ioc_type, risk_level, results)
        
        # Format output
        output = {
            "ioc": ioc,
            "ioc_type": ioc_type,
            "risk_assessment": {
                "risk_level": risk_level,
                "risk_score": risk_score,
                "factors": risk_factors
            },
            "intelligence_sources": results,
            "kql_queries": kql_queries,
            "recommendations": recommendations,
            "analysis_timestamp": "UTC"
        }
        
        return [TextContent(
            type="text",
            text=json.dumps(output, indent=2)
        )]
    
    return [TextContent(
        type="text",
        text=f"Unknown tool: {name}"
    )]


async def main():
    """Run the MCP server"""
    from mcp.server.stdio import stdio_server
    
    logger.info("Starting Multi-Source Threat Intelligence MCP Server")
    logger.info("Aviation Cybersecurity Focus - 9+ Intelligence Sources")
    
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options()
        )


if __name__ == "__main__":
    asyncio.run(main())
