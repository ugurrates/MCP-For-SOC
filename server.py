#!/usr/bin/env python3
"""
Multi-Source Threat Intelligence MCP Server v2.0
Aviation-focused threat intelligence with sandbox analysis and normalized IOC scoring
Author: Ugur Ates
"""

import asyncio
import base64
import hashlib
import json
import logging
import re
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import aiohttp
from mcp.server import Server
from mcp.types import Resource, Tool, TextContent

# C2 Detection signatures
from c2_signatures import (
    C2_FRAMEWORKS, MALWARE_FAMILIES, ATTACK_TOOLS, BOTNETS,
    ALL_MALICIOUS_KEYWORDS, SHODAN_C2_PATTERNS, C2_TRACKER_REPOS,
    C2_SCORING_WEIGHTS, get_malware_category
)

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
    'ALIENVAULT_OTX_API_KEY': '',
    'HYBRID_ANALYSIS_API_KEY': '',
    'ANYRUN_API_KEY': '',
    'TRIAGE_API_KEY': '',
    'THREAT_ZONE_API_KEY': ''
}

# MCP Server instance
server = Server("threat-intelligence-mcp-v2")

# MITRE ATT&CK Framework Mapping
MITRE_TACTICS = {
    'reconnaissance': 'TA0043',
    'resource-development': 'TA0042',
    'initial-access': 'TA0001',
    'execution': 'TA0002',
    'persistence': 'TA0003',
    'privilege-escalation': 'TA0004',
    'defense-evasion': 'TA0005',
    'credential-access': 'TA0006',
    'discovery': 'TA0007',
    'lateral-movement': 'TA0008',
    'collection': 'TA0009',
    'command-and-control': 'TA0011',
    'exfiltration': 'TA0010',
    'impact': 'TA0040'
}


def detect_ioc_type(ioc: str) -> str:
    """Detect IOC type: hash, ip, domain, url, or file"""
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


def calculate_normalized_ioc_score(results: Dict) -> Dict:
    """
    Normalized IOC scoring system (0-100)
    Industry standard framework based on:
    - Threat Score (40%): Actual malicious detections
    - Confidence Score (30%): Source reliability and consensus
    - Impact Score (20%): Vulnerability and criticality
    - Freshness Score (10%): Recency of analysis
    """
    
    threat_score = 0
    confidence_score = 0
    impact_score = 0
    freshness_score = 10  # Default: assume recent
    
    factors = []
    
    # 1. THREAT SCORE (0-40 points)
    # VirusTotal detections
    if 'VirusTotal' in results and 'malicious' in results['VirusTotal']:
        vt = results['VirusTotal']
        total = max(vt.get('total_vendors', 1), 1)
        malicious_ratio = vt['malicious'] / total
        vt_score = min(malicious_ratio * 40, 40)
        threat_score += vt_score
        if vt['malicious'] > 0:
            factors.append(f"VirusTotal: {vt['malicious']}/{total} engines detected malware ({int(malicious_ratio*100)}%)")
    
    # AbuseIPDB confidence
    if 'AbuseIPDB' in results and 'abuse_confidence_score' in results['AbuseIPDB']:
        abuse_confidence = results['AbuseIPDB']['abuse_confidence_score']
        abuse_score = (abuse_confidence / 100) * 15
        threat_score += abuse_score
        if abuse_confidence > 50:
            factors.append(f"AbuseIPDB: {abuse_confidence}% abuse confidence with {results['AbuseIPDB'].get('total_reports', 0)} reports")
    
    # Sandbox threat scores
    sandbox_scores = []
    
    if 'Hybrid-Analysis' in results and 'threat_score' in results['Hybrid-Analysis']:
        ha_score = results['Hybrid-Analysis']['threat_score']
        sandbox_scores.append(ha_score)
        if ha_score >= 70:
            factors.append(f"Hybrid Analysis: Threat score {ha_score}/100")
    
    if 'ANY.RUN' in results and 'verdict' in results['ANY.RUN']:
        verdict = results['ANY.RUN']['verdict'].lower()
        if verdict in ['malicious', 'suspicious']:
            sandbox_scores.append(80 if verdict == 'malicious' else 50)
            factors.append(f"ANY.RUN: Verdict '{verdict}'")
    
    if 'Tria.ge' in results and 'score' in results['Tria.ge']:
        triage_score = results['Tria.ge']['score']
        sandbox_scores.append(triage_score)
        if triage_score >= 7:
            factors.append(f"Tria.ge: Malware score {triage_score}/10")
    
    if 'Threat.Zone' in results and 'threat_level' in results['Threat.Zone']:
        threat_level = results['Threat.Zone']['threat_level']
        level_scores = {'critical': 100, 'high': 80, 'medium': 50, 'low': 20}
        tz_score = level_scores.get(threat_level.lower(), 0)
        sandbox_scores.append(tz_score)
        if tz_score >= 50:
            factors.append(f"Threat.Zone: Threat level '{threat_level}'")
    
    if sandbox_scores:
        avg_sandbox = sum(sandbox_scores) / len(sandbox_scores)
        threat_score += (avg_sandbox / 100) * 20
    
    # Cap threat score at 40
    threat_score = min(threat_score, 40)
    
    # 2. CONFIDENCE SCORE (0-30 points)
    source_count = len([k for k in results.keys() if not k.startswith('_')])
    
    if source_count >= 7:
        confidence_score = 30
        factors.append(f"High confidence: {source_count} intelligence sources analyzed")
    elif source_count >= 5:
        confidence_score = 25
        factors.append(f"Good confidence: {source_count} intelligence sources")
    elif source_count >= 3:
        confidence_score = 20
    else:
        confidence_score = 10
    
    # Consensus bonus
    malicious_sources = 0
    if 'VirusTotal' in results and results['VirusTotal'].get('malicious', 0) > 5:
        malicious_sources += 1
    if 'AbuseIPDB' in results and results['AbuseIPDB'].get('abuse_confidence_score', 0) > 75:
        malicious_sources += 1
    
    # VirusTotal Community Intelligence Bonus
    if 'VirusTotal-Comments' in results:
        vt_comments = results['VirusTotal-Comments']
        if 'comments' in vt_comments and len(vt_comments['comments']) > 0:
            # Positive votes indicate trusted community feedback
            total_positive_votes = sum(c.get('votes', {}).get('positive', 0) for c in vt_comments['comments'])
            if total_positive_votes >= 10:
                confidence_score += 5
                factors.append(f"💬 Strong community validation ({total_positive_votes} positive votes on VT comments)")
            elif total_positive_votes >= 3:
                confidence_score += 3
                factors.append(f"💬 Community feedback available ({total_positive_votes} positive votes)")
    
    if any('Hybrid-Analysis' in results, 'ANY.RUN' in results, 'Tria.ge' in results, 'Threat.Zone' in results):
        if sandbox_scores and sum(sandbox_scores) / len(sandbox_scores) > 60:
            malicious_sources += 1
    
    if malicious_sources >= 3:
        confidence_score = min(confidence_score + 5, 30)
        factors.append("Strong consensus across multiple threat intelligence sources")
    
    # 3. IMPACT SCORE (0-20 points)
    # Vulnerabilities from Shodan
    if 'Shodan' in results and 'vulns' in results['Shodan']:
        vuln_count = len(results['Shodan']['vulns'])
        if vuln_count > 0:
            impact_score += min(vuln_count * 5, 15)
            factors.append(f"Shodan: {vuln_count} known vulnerabilities detected")
    
    # AlienVault threat pulses
    if 'AlienVault OTX' in results and 'pulse_count' in results['AlienVault OTX']:
        pulse_count = results['AlienVault OTX']['pulse_count']
        if pulse_count > 20:
            impact_score += 10
            factors.append(f"AlienVault OTX: Referenced in {pulse_count} threat intelligence pulses")
        elif pulse_count > 10:
            impact_score += 7
            factors.append(f"AlienVault OTX: {pulse_count} threat pulses")
        elif pulse_count > 0:
            impact_score += 4
    
    # Abuse.ch presence
    if 'Abuse.ch' in results and results['Abuse.ch'].get('results'):
        impact_score += 8
        factors.append("Found in Abuse.ch malware databases")
    
    # C2 TRACKER DETECTION (HIGH PRIORITY)
    if 'C2-Trackers' in results and results['C2-Trackers'].get('status') == 'CONFIRMED_C2_INFRASTRUCTURE':
        c2_trackers = results['C2-Trackers']
        tracker_count = c2_trackers.get('total_trackers_matched', 0)
        # C2 infrastructure is critical - add significant score
        impact_score += min(tracker_count * 10, 20)  # Up to 20 points
        threat_score += 30  # Additional threat score for confirmed C2
        factors.append(f"⚠️ CONFIRMED C2 INFRASTRUCTURE - Found in {tracker_count} C2 tracker database(s)")
    
    # USOM TURKISH NATIONAL THREAT INTEL
    if 'USOM-Turkey' in results and results['USOM-Turkey'].get('status') == 'LISTED_AS_MALICIOUS':
        impact_score += 15
        threat_score += 25
        factors.append("🇹🇷 LISTED IN USOM (Turkish National Threat Database)")
    
    # DOMAIN ENTROPY / SUSPICIOUS PATTERN
    if '_domain_analysis' in results and results['_domain_analysis'].get('is_suspicious'):
        domain_analysis = results['_domain_analysis']
        confidence = domain_analysis.get('confidence', 'low')
        
        if confidence == 'high':
            impact_score += 10
            threat_score += 15
            factors.append(f"🔍 HIGH CONFIDENCE Suspicious Domain Pattern: {', '.join(domain_analysis.get('suspicious_factors', []))}")
        elif confidence == 'medium':
            impact_score += 6
            threat_score += 8
            factors.append(f"⚡ Suspicious Domain Pattern: {domain_analysis.get('verdict', 'Unknown')}")
    
    # SHODAN C2 KEYWORD DETECTION
    if '_shodan_c2_analysis' in results and results['_shodan_c2_analysis'].get('is_likely_c2'):
        c2_analysis = results['_shodan_c2_analysis']
        confidence = c2_analysis.get('confidence', 'low')
        keyword_count = len(c2_analysis.get('c2_keywords', []))
        pattern_count = len(c2_analysis.get('c2_patterns', []))
        
        if confidence == 'high':
            impact_score += 15
            threat_score += 25
            factors.append(f"🚨 HIGH CONFIDENCE C2 Detection: {keyword_count} malicious keywords, {pattern_count} C2 patterns")
        elif confidence == 'medium':
            impact_score += 10
            threat_score += 15
            factors.append(f"⚠️ MEDIUM CONFIDENCE C2 Detection: {keyword_count} malicious keywords")
        else:
            impact_score += 5
            threat_score += 8
            factors.append(f"⚡ Possible C2 indicators: {keyword_count} keywords detected")
        
        # Add specific C2 framework/malware names
        for detection in c2_analysis.get('c2_keywords', [])[:3]:  # Top 3
            factors.append(f"  └─ {detection['category']}: {detection['keyword']}")
    
    # MITRE ATT&CK tactics
    if '_mitre_tactics' in results and results['_mitre_tactics']:
        tactic_count = len(results['_mitre_tactics'])
        impact_score += min(tactic_count * 2, 10)
        if tactic_count > 0:
            factors.append(f"MITRE ATT&CK: {tactic_count} tactics identified")
    
    impact_score = min(impact_score, 20)
    
    # 4. FRESHNESS SCORE (0-10 points)
    # For now, default to 10 (recent analysis)
    # In future: decay based on last_seen timestamp
    
    # FINAL CALCULATION
    final_score = min(threat_score + confidence_score + impact_score + freshness_score, 100)
    
    # SEVERITY CLASSIFICATION
    if final_score >= 90:
        severity = "CRITICAL"
        color = "#dc2626"  # red-600
        priority = "P1"
    elif final_score >= 70:
        severity = "HIGH"
        color = "#ea580c"  # orange-600
        priority = "P2"
    elif final_score >= 40:
        severity = "MEDIUM"
        color = "#ca8a04"  # yellow-600
        priority = "P3"
    elif final_score >= 20:
        severity = "LOW"
        color = "#2563eb"  # blue-600
        priority = "P4"
    else:
        severity = "MINIMAL"
        color = "#16a34a"  # green-600
        priority = "P5"
    
    return {
        "final_score": round(final_score, 2),
        "severity": severity,
        "priority": priority,
        "color": color,
        "breakdown": {
            "threat_score": round(threat_score, 2),
            "confidence_score": round(confidence_score, 2),
            "impact_score": round(impact_score, 2),
            "freshness_score": round(freshness_score, 2)
        },
        "contributing_factors": factors,
        "sources_analyzed": source_count,
        "analysis_timestamp": datetime.utcnow().isoformat() + "Z"
    }


def extract_network_iocs_from_sandbox(results: Dict) -> Dict:
    """Extract network IOCs from sandbox analysis results"""
    network_iocs = {
        'ips': set(),
        'domains': set(),
        'urls': set()
    }
    
    # Hybrid Analysis
    if 'Hybrid-Analysis' in results:
        ha = results['Hybrid-Analysis']
        if 'network_iocs' in ha:
            network_iocs['ips'].update(ha['network_iocs'].get('ips', []))
            network_iocs['domains'].update(ha['network_iocs'].get('domains', []))
            network_iocs['urls'].update(ha['network_iocs'].get('urls', []))
    
    # ANY.RUN
    if 'ANY.RUN' in results:
        ar = results['ANY.RUN']
        if 'network' in ar:
            network_iocs['ips'].update(ar['network'].get('ips', []))
            network_iocs['domains'].update(ar['network'].get('domains', []))
    
    # Tria.ge
    if 'Tria.ge' in results:
        tg = results['Tria.ge']
        if 'network' in tg:
            for conn in tg['network'].get('connections', []):
                if 'ip' in conn:
                    network_iocs['ips'].add(conn['ip'])
                if 'domain' in conn:
                    network_iocs['domains'].add(conn['domain'])
    
    # Threat.Zone
    if 'Threat.Zone' in results:
        tz = results['Threat.Zone']
        if 'iocs' in tz:
            network_iocs['ips'].update(tz['iocs'].get('ips', []))
            network_iocs['domains'].update(tz['iocs'].get('domains', []))
            network_iocs['urls'].update(tz['iocs'].get('urls', []))
    
    return {
        'ips': sorted(list(network_iocs['ips'])),
        'domains': sorted(list(network_iocs['domains'])),
        'urls': sorted(list(network_iocs['urls'])),
        'total_iocs': len(network_iocs['ips']) + len(network_iocs['domains']) + len(network_iocs['urls'])
    }


def map_to_mitre_attck(results: Dict) -> List[Dict]:
    """Map sandbox behaviors to MITRE ATT&CK framework"""
    tactics = []
    
    # Hybrid Analysis MITRE mapping
    if 'Hybrid-Analysis' in results and 'mitre_attcks' in results['Hybrid-Analysis']:
        for attck in results['Hybrid-Analysis']['mitre_attcks']:
            tactics.append({
                'tactic': attck.get('tactic', 'unknown'),
                'technique': attck.get('technique', 'unknown'),
                'technique_id': attck.get('technique_id', ''),
                'source': 'Hybrid Analysis'
            })
    
    # ANY.RUN tactics
    if 'ANY.RUN' in results and 'mitre_matrix' in results['ANY.RUN']:
        for tactic in results['ANY.RUN']['mitre_matrix']:
            tactics.append({
                'tactic': tactic.get('tactic', 'unknown'),
                'technique': tactic.get('technique', 'unknown'),
                'technique_id': tactic.get('id', ''),
                'source': 'ANY.RUN'
            })
    
    # Tria.ge signatures to MITRE mapping
    if 'Tria.ge' in results and 'signatures' in results['Tria.ge']:
        # Map common signatures to tactics
        sig_mappings = {
            'network': 'command-and-control',
            'persistence': 'persistence',
            'escalation': 'privilege-escalation',
            'evasion': 'defense-evasion',
            'credential': 'credential-access',
            'discovery': 'discovery',
            'execution': 'execution'
        }
        
        for sig in results['Tria.ge']['signatures']:
            sig_name = sig.lower()
            for keyword, tactic in sig_mappings.items():
                if keyword in sig_name:
                    tactics.append({
                        'tactic': tactic,
                        'technique': sig,
                        'technique_id': '',
                        'source': 'Tria.ge'
                    })
                    break
    
    # Deduplicate and return
    unique_tactics = []
    seen = set()
    for tactic in tactics:
        key = (tactic['tactic'], tactic['technique_id'] or tactic['technique'])
        if key not in seen:
            seen.add(key)
            unique_tactics.append(tactic)
    
    return unique_tactics


# ==================== VIRUSTOTAL WITH FILE UPLOAD ====================

async def query_virustotal_comments(session: aiohttp.ClientSession, ioc: str, ioc_type: str) -> Dict:
    """Query VirusTotal comments for community intelligence"""
    config = load_config()
    api_key = config['api_keys'].get('virustotal')
    
    if not api_key:
        return {"error": "VirusTotal API key not configured"}
    
    headers = {"x-apikey": api_key}
    
    # Map IOC type to VT endpoint
    endpoint_map = {
        'ip': f'ip_addresses/{ioc}',
        'domain': f'domains/{ioc}',
        'url': f'urls/{ioc}',
        'hash_md5': f'files/{ioc}',
        'hash_sha1': f'files/{ioc}',
        'hash_sha256': f'files/{ioc}'
    }
    
    endpoint = endpoint_map.get(ioc_type)
    if not endpoint:
        return {"error": f"Unsupported IOC type for comments: {ioc_type}"}
    
    try:
        url = f"https://www.virustotal.com/api/v3/{endpoint}/comments"
        
        async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as response:
            if response.status == 200:
                data = await response.json()
                
                # Extract comments
                comments = []
                for item in data.get('data', [])[:10]:  # Top 10 comments
                    attrs = item.get('attributes', {})
                    
                    # Get author username if available
                    author = "Anonymous"
                    if 'relationships' in item:
                        author_data = item.get('relationships', {}).get('author', {}).get('data', {})
                        author = author_data.get('id', 'Anonymous')
                    
                    comment = {
                        'text': attrs.get('text', ''),
                        'date': attrs.get('date'),
                        'votes': attrs.get('votes', {}),
                        'author': author
                    }
                    
                    # Only include non-empty comments
                    if comment['text']:
                        comments.append(comment)
                
                return {
                    "total_comments": len(data.get('data', [])),
                    "comments_shown": len(comments),
                    "comments": comments
                }
            elif response.status == 404:
                return {"status": "no_comments"}
            else:
                return {"error": f"HTTP {response.status}"}
                
    except Exception as e:
        logger.error(f"VirusTotal comments query error: {e}")
        return {"error": str(e)}


async def query_virustotal(session: aiohttp.ClientSession, ioc: str, ioc_type: str) -> Dict:
    """Query VirusTotal API with file upload support"""
    if not API_KEYS.get('VIRUSTOTAL_API_KEY'):
        return {"error": "VirusTotal API key not configured"}
    
    headers = {'x-apikey': API_KEYS['VIRUSTOTAL_API_KEY']}
    
    try:
        if ioc_type == 'url':
            url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip('=')
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


async def upload_file_to_virustotal(session: aiohttp.ClientSession, file_path: str) -> Dict:
    """Upload file to VirusTotal for analysis"""
    if not API_KEYS.get('VIRUSTOTAL_API_KEY'):
        return {"error": "VirusTotal API key not configured"}
    
    headers = {'x-apikey': API_KEYS['VIRUSTOTAL_API_KEY']}
    
    try:
        with open(file_path, 'rb') as f:
            files = {'file': f}
            async with session.post('https://www.virustotal.com/api/v3/files',
                                  headers=headers,
                                  data=files,
                                  timeout=aiohttp.ClientTimeout(total=120)) as response:
                if response.status == 200:
                    data = await response.json()
                    analysis_id = data['data']['id']
                    return {
                        "status": "submitted",
                        "analysis_id": analysis_id,
                        "message": "File submitted successfully. Analysis in progress."
                    }
                else:
                    return {"error": f"Upload failed: {response.status}"}
    except Exception as e:
        logger.error(f"VirusTotal upload error: {e}")
        return {"error": str(e)}


# ==================== HYBRID ANALYSIS ====================

async def query_hybrid_analysis(session: aiohttp.ClientSession, file_hash: str) -> Dict:
    """Query Hybrid Analysis API"""
    if not API_KEYS.get('HYBRID_ANALYSIS_API_KEY'):
        return {"error": "Hybrid Analysis API key not configured"}
    
    headers = {
        'api-key': API_KEYS['HYBRID_ANALYSIS_API_KEY'],
        'user-agent': 'Falcon Sandbox'
    }
    
    try:
        # Search by hash
        data = {'hash': file_hash}
        async with session.post('https://www.hybrid-analysis.com/api/v2/search/hash',
                               headers=headers,
                               data=data,
                               timeout=aiohttp.ClientTimeout(total=30)) as response:
            if response.status == 404:
                return {"status": "not_found", "message": "Hash not found in Hybrid Analysis"}
            elif response.status == 429:
                return {"error": "Rate limit exceeded"}
            elif response.status != 200:
                return {"error": f"API error: {response.status}"}
            
            results = await response.json()
            
            if not results:
                return {"status": "not_found", "message": "No analysis found"}
            
            # Get most recent analysis
            analysis = results[0]
            
            return {
                "source": "Hybrid-Analysis",
                "verdict": analysis.get('verdict', 'unknown'),
                "threat_score": analysis.get('threat_score', 0),
                "threat_level": analysis.get('threat_level', 0),
                "av_detect": analysis.get('av_detect', 0),
                "vx_family": analysis.get('vx_family', 'N/A'),
                "mitre_attcks": analysis.get('mitre_attcks', []),
                "network_iocs": {
                    "ips": analysis.get('hosts', []),
                    "domains": analysis.get('domains', []),
                    "urls": []
                },
                "analysis_date": analysis.get('analysis_start_time', 'N/A')
            }
            
    except Exception as e:
        logger.error(f"Hybrid Analysis query error: {e}")
        return {"error": str(e)}


# ==================== ANY.RUN ====================

async def query_anyrun(session: aiohttp.ClientSession, file_hash: str) -> Dict:
    """Query ANY.RUN API"""
    if not API_KEYS.get('ANYRUN_API_KEY'):
        return {"error": "ANY.RUN API key not configured"}
    
    headers = {'Authorization': f'API-Key {API_KEYS["ANYRUN_API_KEY"]}'}
    
    try:
        params = {'hash': file_hash}
        async with session.get('https://api.any.run/v1/analysis',
                              headers=headers,
                              params=params,
                              timeout=aiohttp.ClientTimeout(total=30)) as response:
            if response.status == 404:
                return {"status": "not_found", "message": "Hash not found in ANY.RUN"}
            elif response.status == 429:
                return {"error": "Rate limit exceeded"}
            elif response.status != 200:
                return {"error": f"API error: {response.status}"}
            
            data = await response.json()
            
            if 'data' in data and data['data']:
                analysis = data['data'][0]
                
                return {
                    "source": "ANY.RUN",
                    "verdict": analysis.get('verdict', 'unknown'),
                    "malware_families": analysis.get('malware_families', []),
                    "tags": analysis.get('tags', []),
                    "mitre_matrix": analysis.get('mitre_matrix', []),
                    "network": {
                        "ips": analysis.get('network', {}).get('ips', []),
                        "domains": analysis.get('network', {}).get('domains', [])
                    },
                    "analysis_date": analysis.get('date', 'N/A')
                }
            
            return {"status": "not_found"}
            
    except Exception as e:
        logger.error(f"ANY.RUN query error: {e}")
        return {"error": str(e)}


# ==================== TRIA.GE ====================

async def query_triage(session: aiohttp.ClientSession, file_hash: str) -> Dict:
    """Query Tria.ge (Hatching) API"""
    if not API_KEYS.get('TRIAGE_API_KEY'):
        return {"error": "Tria.ge API key not configured"}
    
    headers = {'Authorization': f'Bearer {API_KEYS["TRIAGE_API_KEY"]}'}
    
    try:
        async with session.get(f'https://api.tria.ge/v0/samples/{file_hash}/overview',
                              headers=headers,
                              timeout=aiohttp.ClientTimeout(total=30)) as response:
            if response.status == 404:
                return {"status": "not_found", "message": "Hash not found in Tria.ge"}
            elif response.status == 429:
                return {"error": "Rate limit exceeded"}
            elif response.status != 200:
                return {"error": f"API error: {response.status}"}
            
            data = await response.json()
            
            return {
                "source": "Tria.ge",
                "score": data.get('score', 0),
                "family": data.get('family', 'N/A'),
                "signatures": data.get('signatures', []),
                "targets": data.get('targets', []),
                "network": data.get('network', {}),
                "analysis_date": data.get('submitted', 'N/A')
            }
            
    except Exception as e:
        logger.error(f"Tria.ge query error: {e}")
        return {"error": str(e)}


# ==================== THREAT.ZONE ====================

async def query_threat_zone(session: aiohttp.ClientSession, file_hash: str) -> Dict:
    """Query Threat.Zone API"""
    if not API_KEYS.get('THREAT_ZONE_API_KEY'):
        return {"error": "Threat.Zone API key not configured"}
    
    headers = {'Authorization': f'Bearer {API_KEYS["THREAT_ZONE_API_KEY"]}'}
    
    try:
        # Search for existing analysis
        params = {'sha256': file_hash}
        async with session.get('https://app.threat.zone/api/v1/submission/search',
                              headers=headers,
                              params=params,
                              timeout=aiohttp.ClientTimeout(total=30)) as response:
            if response.status == 404:
                return {"status": "not_found", "message": "Hash not found in Threat.Zone"}
            elif response.status == 429:
                return {"error": "Rate limit exceeded"}
            elif response.status != 200:
                return {"error": f"API error: {response.status}"}
            
            data = await response.json()
            
            if data.get('data'):
                submission = data['data'][0]
                uuid = submission['uuid']
                
                # Get detailed analysis
                async with session.get(f'https://app.threat.zone/api/v1/submission/{uuid}',
                                      headers=headers,
                                      timeout=aiohttp.ClientTimeout(total=30)) as detail_response:
                    if detail_response.status == 200:
                        detail = await detail_response.json()
                        
                        # Get IOCs
                        iocs = {}
                        async with session.get(f'https://app.threat.zone/api/v1/submission/{uuid}/iocs',
                                              headers=headers,
                                              timeout=aiohttp.ClientTimeout(total=30)) as ioc_response:
                            if ioc_response.status == 200:
                                iocs = await ioc_response.json()
                        
                        return {
                            "source": "Threat.Zone",
                            "threat_level": detail.get('threat_level', 'unknown'),
                            "score": detail.get('score', 0),
                            "family": detail.get('family', 'N/A'),
                            "tags": detail.get('tags', []),
                            "iocs": {
                                "ips": iocs.get('ips', []),
                                "domains": iocs.get('domains', []),
                                "urls": iocs.get('urls', [])
                            },
                            "analysis_date": detail.get('created_at', 'N/A')
                        }
            
            return {"status": "not_found"}
            
    except Exception as e:
        logger.error(f"Threat.Zone query error: {e}")
        return {"error": str(e)}



# ==================== EXISTING SOURCES (from v1) ====================

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



# ==================== KQL QUERY GENERATION ====================

def generate_kql_queries(ioc: str, ioc_type: str, severity: str, network_iocs: Dict) -> List[str]:
    """Generate Microsoft Defender EDR KQL queries"""
    queries = []
    
    # Base queries for IOC type
    if ioc_type == 'ip':
        queries.extend([
            f'// Hunt for network connections to malicious IP\nDeviceNetworkEvents\n| where RemoteIP == "{ioc}"\n| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, InitiatingProcessFileName\n| sort by Timestamp desc',
            f'// Summarize affected devices\nDeviceNetworkEvents\n| where RemoteIP == "{ioc}" and ActionType == "ConnectionSuccess"\n| summarize ConnectionCount=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by DeviceName, InitiatingProcessFileName',
            f'// Check for process command lines referencing IP\nDeviceProcessEvents\n| where ProcessCommandLine has "{ioc}"\n| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName'
        ])
    
    elif ioc_type == 'domain':
        queries.extend([
            f'// Hunt for DNS queries and network connections\nDeviceNetworkEvents\n| where RemoteUrl has "{ioc}"\n| project Timestamp, DeviceName, RemoteUrl, RemoteIP, InitiatingProcessFileName, ActionType\n| sort by Timestamp desc',
            f'// Check email URLs\nEmailUrlInfo\n| where Url has "{ioc}"\n| project Timestamp, SenderFromAddress, RecipientEmailAddress, Url, UrlLocation',
            f'// File events with domain reference\nDeviceFileEvents\n| where FolderPath has "{ioc}" or InitiatingProcessCommandLine has "{ioc}"\n| project Timestamp, DeviceName, FileName, FolderPath'
        ])
    
    elif ioc_type == 'url':
        domain = extract_domain_from_url(ioc)
        queries.extend([
            f'// Hunt for exact URL access\nDeviceNetworkEvents\n| where RemoteUrl == "{ioc}"\n| project Timestamp, DeviceName, ActionType, RemoteUrl, InitiatingProcessFileName',
            f'// Email with malicious URL\nEmailUrlInfo\n| where Url == "{ioc}"\n| join kind=inner (EmailEvents) on NetworkMessageId\n| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, Url',
            f'// Network events to domain\nDeviceNetworkEvents\n| where RemoteUrl has "{domain}"\n| summarize count() by DeviceName, InitiatingProcessFileName, RemoteUrl'
        ])
    
    elif 'hash' in ioc_type:
        hash_type = ioc_type.split('_')[1].upper()
        queries.extend([
            f'// Hunt for file by hash\nDeviceFileEvents\n| where {hash_type} == "{ioc}"\n| project Timestamp, DeviceName, FileName, FolderPath, FileOriginUrl, {hash_type}\n| sort by Timestamp desc',
            f'// Process execution by hash\nDeviceProcessEvents\n| where {hash_type} == "{ioc}"\n| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine, AccountName',
            f'// Image load events\nDeviceImageLoadEvents\n| where {hash_type} == "{ioc}"\n| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName'
        ])
    
    # Add queries for extracted network IOCs
    if network_iocs and network_iocs.get('total_iocs', 0) > 0:
        if network_iocs.get('ips'):
            ip_list = '", "'.join(network_iocs['ips'][:10])  # Limit to top 10
            queries.append(f'// Hunt for related malicious IPs from sandbox\nDeviceNetworkEvents\n| where RemoteIP in ("{ip_list}")\n| summarize count() by RemoteIP, DeviceName, InitiatingProcessFileName\n| sort by count_ desc')
        
        if network_iocs.get('domains'):
            domain_list = '", "'.join(network_iocs['domains'][:10])
            queries.append(f'// Hunt for related malicious domains from sandbox\nDeviceNetworkEvents\n| where RemoteUrl has_any ("{domain_list}")\n| summarize count() by RemoteUrl, DeviceName\n| sort by count_ desc')
    
    # Critical severity - add comprehensive hunting query
    if severity in ["CRITICAL", "HIGH"]:
        queries.append(f'// Comprehensive 30-day hunt\nDeviceEvents\n| where Timestamp > ago(30d)\n| search "{ioc}"\n| summarize EventCount=count(), EventTypes=make_set(ActionType) by DeviceName, InitiatingProcessFileName\n| sort by EventCount desc')
    
    return queries


def generate_recommendations(ioc: str, ioc_type: str, severity: str, score_data: Dict, results: Dict) -> List[str]:
    """Generate actionable recommendations based on severity"""
    recommendations = []
    
    if severity == "CRITICAL":
        recommendations.extend([
            f"🚨 CRITICAL THREAT DETECTED - Immediate action required",
            f"IOC Score: {score_data['final_score']}/100 | Priority: {score_data['priority']}",
            "",
            "IMMEDIATE ACTIONS (Next 15 minutes):",
            f"1. BLOCK {ioc_type.upper()}: {ioc} across all security controls:",
            "   - Firewall rules (perimeter and internal)",
            "   - EDR/XDR block lists (Defender, CrowdStrike, etc.)",
            "   - Proxy/Web gateway",
            "   - Email gateway (if applicable)",
            "",
            "2. HUNT for existing activity:",
            "   - Run provided KQL queries in Defender portal",
            "   - Check SIEM for historical matches (QRadar, Splunk)",
            "   - Review proxy logs for connections",
            "",
            "3. ISOLATE affected systems:",
            "   - Identify endpoints from hunting queries",
            "   - Network isolate via EDR",
            "   - Disable user accounts if compromised",
            "",
            "4. INCIDENT RESPONSE:",
            "   - Trigger IR playbook",
            "   - Collect forensic evidence (memory, disk)",
            "   - Document timeline of compromise",
            "",
            "5. NOTIFY stakeholders:",
            "   - Security leadership",
            "   - Affected business units",
            "   - Prepare breach assessment"
        ])
        
    elif severity == "HIGH":
        recommendations.extend([
            f"⚠️ HIGH RISK DETECTED - Urgent investigation required",
            f"IOC Score: {score_data['final_score']}/100 | Priority: {score_data['priority']}",
            "",
            "PRIORITY ACTIONS (Next 2 hours):",
            "1. MONITOR and prepare to block:",
            "   - Add to watchlist in SIEM",
            "   - Enable enhanced logging",
            "   - Prepare block rules (don't deploy yet)",
            "",
            "2. INVESTIGATE:",
            "   - Run hunting queries",
            "   - Review recent access logs",
            "   - Check for lateral movement indicators",
            "",
            "3. RISK ASSESSMENT:",
            "   - Determine business impact",
            "   - Identify affected assets",
            "   - Consider temporary blocking pending investigation",
            "",
            "4. CONTAINMENT (if evidence found):",
            "   - Isolate affected systems",
            "   - Block IOC",
            "   - Escalate to incident response"
        ])
        
    elif severity == "MEDIUM":
        recommendations.extend([
            f"🔍 MEDIUM RISK - Investigation recommended",
            f"IOC Score: {score_data['final_score']}/100 | Priority: {score_data['priority']}",
            "",
            "STANDARD ACTIONS (Next 24 hours):",
            "1. ADD TO WATCHLIST:",
            "   - Monitor in SIEM",
            "   - Track via threat intelligence platform",
            "",
            "2. INVESTIGATE:",
            "   - Run hunting queries during next sweep",
            "   - Review logs for suspicious patterns",
            "",
            "3. DOCUMENT:",
            "   - Add to threat intel database",
            "   - Update detection rules if needed",
            "   - Share with SOC team"
        ])
        
    elif severity == "LOW":
        recommendations.extend([
            f"📊 LOW RISK - Standard monitoring",
            f"IOC Score: {score_data['final_score']}/100 | Priority: {score_data['priority']}",
            "",
            "ROUTINE ACTIONS:",
            "1. ADD TO MONITORING:",
            "   - Document in threat intel platform",
            "   - Include in weekly threat reports",
            "",
            "2. PASSIVE MONITORING:",
            "   - Check during regular log reviews",
            "   - No active hunting required"
        ])
        
    else:  # MINIMAL
        recommendations.extend([
            f"✅ MINIMAL RISK - No immediate action required",
            f"IOC Score: {score_data['final_score']}/100 | Priority: {score_data['priority']}",
            "",
            "INFORMATIONAL:",
            "1. IOC appears benign based on available intelligence",
            "2. Continue standard security monitoring",
            "3. No specific actions required"
        ])
    
    # Add contextual recommendations based on findings
    recommendations.append("")
    recommendations.append("CONTEXTUAL FINDINGS:")
    
    if '_mitre_tactics' in results and results['_mitre_tactics']:
        tactic_names = [t['tactic'] for t in results['_mitre_tactics']]
        recommendations.append(f"- MITRE ATT&CK Tactics: {', '.join(set(tactic_names))}")
    
    if '_network_iocs' in results and results['_network_iocs']['total_iocs'] > 0:
        recommendations.append(f"- Related Network IOCs found: {results['_network_iocs']['total_iocs']} (IPs, domains, URLs)")
        recommendations.append(f"  Consider hunting for these as well")
    
    for source in ['Hybrid-Analysis', 'ANY.RUN', 'Tria.ge', 'Threat.Zone']:
        if source in results and 'family' in results[source]:
            family = results[source]['family']
            if family and family != 'N/A':
                recommendations.append(f"- Malware Family: {family} (detected by {source})")
    
    return recommendations



# ==================== MCP TOOL DEFINITIONS ====================

@server.list_tools()
async def list_tools() -> List[Tool]:
    """List available MCP tools"""
    return [
        Tool(
            name="analyze_threat",
            description="Comprehensive threat intelligence analysis with multi-platform detection rule generation. "
                       "Analyzes IPs, domains, URLs, and file hashes across 17+ intelligence sources including "
                       "C2 trackers, sandbox platforms, Turkish national threat intel (USOM), and community insights. "
                       "Features: Normalized IOC scoring (0-100), MITRE ATT&CK mapping, network IOC extraction, "
                       "domain entropy analysis, malware family identification, JARM/JA3 C2 fingerprinting, and "
                       "VirusTotal community intelligence (researcher comments and votes). "
                       "Generates ready-to-use detection rules for: KQL (Microsoft Defender), SPL (Splunk), "
                       "SIGMA (Universal SIEM), XQL (Cortex XDR), and YARA (Malware Detection). "
                       "Sources: VirusTotal + Comments, Hybrid Analysis, ANY.RUN, Tria.ge, Threat.Zone, AbuseIPDB, "
                       "Shodan, AlienVault OTX, Abuse.ch, C2 Trackers (Daily Malware, JMousqueton, C2Live), USOM.",
            inputSchema={
                "type": "object",
                "properties": {
                    "ioc": {
                        "type": "string",
                        "description": "Indicator of Compromise: IP address, domain, URL, or file hash (MD5/SHA1/SHA256)"
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
                text=f"Error: Unable to detect IOC type for: {ioc}\nSupported types: IP, domain, URL, hash (MD5/SHA1/SHA256)"
            )]
        
        logger.info(f"[ANALYSIS START] {ioc_type.upper()}: {ioc}")
        
        # Phase 1: Multi-source threat intelligence gathering
        results = {}
        start_time = time.time()
        
        async with aiohttp.ClientSession() as session:
            tasks = []
            
            # Core intelligence sources (all IOC types)
            tasks.append(('VirusTotal', query_virustotal(session, ioc, ioc_type)))
            tasks.append(('VirusTotal-Comments', query_virustotal_comments(session, ioc, ioc_type)))
            tasks.append(('AlienVault OTX', query_alienvault_otx(session, ioc, ioc_type)))
            tasks.append(('Abuse.ch', query_abuse_ch(session, ioc, ioc_type)))
            
            # C2 Tracker sources (IP, domain, hash)
            if ioc_type in ['ip', 'domain'] or 'hash' in ioc_type:
                tasks.append(('C2-Trackers', query_c2_trackers(session, ioc, ioc_type)))
            
            # USOM Turkish National Threat Intel (IP, domain, URL)
            if ioc_type in ['ip', 'domain', 'url']:
                tasks.append(('USOM-Turkey', query_usom_malicious_list(session, ioc, ioc_type)))
            
            # IP-specific sources
            if ioc_type == 'ip':
                tasks.append(('AbuseIPDB', query_abuseipdb(session, ioc)))
                tasks.append(('Shodan', query_shodan(session, ioc)))
            
            # Hash-specific sources (sandbox analysis)
            if 'hash' in ioc_type:
                tasks.append(('Hybrid-Analysis', query_hybrid_analysis(session, ioc)))
                tasks.append(('ANY.RUN', query_anyrun(session, ioc)))
                tasks.append(('Tria.ge', query_triage(session, ioc)))
                tasks.append(('Threat.Zone', query_threat_zone(session, ioc)))
            
            # Execute all queries concurrently
            for source_name, task in tasks:
                try:
                    result = await task
                    if result and 'error' not in result:
                        results[source_name] = result
                        logger.info(f"[{source_name}] Query successful")
                    else:
                        logger.warning(f"[{source_name}] {result.get('error', 'No data')}")
                except Exception as e:
                    logger.error(f"[{source_name}] Query failed: {e}")
        
        query_time = time.time() - start_time
        logger.info(f"[PHASE 1 COMPLETE] {len(results)} sources queried in {query_time:.2f}s")
        
        # Phase 1.5: Enhanced Shodan C2 detection (for IPs)
        if ioc_type == 'ip' and 'Shodan' in results:
            async with aiohttp.ClientSession() as session:
                c2_analysis = await enhanced_shodan_c2_detection(session, ioc, results['Shodan'])
                if c2_analysis['is_likely_c2']:
                    results['_shodan_c2_analysis'] = c2_analysis
                    logger.info(f"[SHODAN-C2] Detected C2 indicators (confidence: {c2_analysis['confidence']})")
        
        # Phase 1.6: Domain entropy analysis (for domains)
        if ioc_type == 'domain':
            entropy_analysis = analyze_domain_entropy(ioc)
            if entropy_analysis['is_suspicious']:
                results['_domain_analysis'] = entropy_analysis
                logger.info(f"[DOMAIN-ENTROPY] Suspicious domain pattern detected (confidence: {entropy_analysis['confidence']})")
        
        # Phase 2: Extract network IOCs from sandbox results
        network_iocs = extract_network_iocs_from_sandbox(results)
        if network_iocs['total_iocs'] > 0:
            results['_network_iocs'] = network_iocs
            logger.info(f"[PHASE 2] Extracted {network_iocs['total_iocs']} network IOCs")
        
        # Phase 3: Map to MITRE ATT&CK
        mitre_tactics = map_to_mitre_attck(results)
        if mitre_tactics:
            results['_mitre_tactics'] = mitre_tactics
            logger.info(f"[PHASE 3] Mapped {len(mitre_tactics)} MITRE ATT&CK tactics")
        
        # Phase 3.5: Extract malware families
        malware_families = extract_malware_families(results)
        if malware_families:
            results['_malware_families'] = malware_families
            logger.info(f"[MALWARE-FAMILIES] Identified: {', '.join(malware_families)}")
        
        # Phase 4: Calculate normalized IOC score
        score_data = calculate_normalized_ioc_score(results)
        logger.info(f"[PHASE 4] IOC Score: {score_data['final_score']}/100 | Severity: {score_data['severity']}")
        
        # Import score_data for YARA rules
        import detection_rules
        detection_rules.score_data = score_data
        
        # Phase 5: Generate multi-platform detection rules
        primary_malware_family = malware_families[0] if malware_families else None
        
        # KQL (Microsoft Defender EDR)
        kql_queries = generate_kql_queries(ioc, ioc_type, score_data['severity'], network_iocs)
        
        # SPL (Splunk)
        spl_queries = generate_spl_queries(ioc, ioc_type, score_data['severity'], network_iocs)
        
        # SIGMA (Universal SIEM)
        sigma_rules = generate_sigma_rules(ioc, ioc_type, score_data['severity'], score_data, primary_malware_family)
        
        # XQL (Cortex XDR)
        xql_queries = generate_xql_queries(ioc, ioc_type, score_data['severity'], network_iocs)
        
        # YARA (Malware detection)
        yara_rules = generate_yara_rules(ioc, ioc_type, score_data['severity'], primary_malware_family, network_iocs)
        
        detection_rules_count = len(kql_queries) + len(spl_queries) + len(sigma_rules) + len(xql_queries) + len(yara_rules)
        logger.info(f"[PHASE 5] Generated {detection_rules_count} detection rules (KQL: {len(kql_queries)}, SPL: {len(spl_queries)}, SIGMA: {len(sigma_rules)}, XQL: {len(xql_queries)}, YARA: {len(yara_rules)})")
        
        # Phase 6: Generate actionable recommendations
        recommendations = generate_recommendations(ioc, ioc_type, score_data['severity'], score_data, results)
        
        # Format output
        output = {
            "ioc": ioc,
            "ioc_type": ioc_type,
            "normalized_score": score_data,
            "intelligence_sources": {k: v for k, v in results.items() if not k.startswith('_')},
            "malware_families": malware_families if malware_families else None,
            "network_iocs": network_iocs if network_iocs['total_iocs'] > 0 else None,
            "mitre_attck": mitre_tactics if mitre_tactics else None,
            "domain_analysis": results.get('_domain_analysis'),
            "detection_rules": {
                "kql_queries": kql_queries,
                "spl_queries": spl_queries,
                "sigma_rules": sigma_rules,
                "xql_queries": xql_queries,
                "yara_rules": yara_rules,
                "total_rules": detection_rules_count
            },
            "recommendations": recommendations,
            "analysis_metadata": {
                "query_time_seconds": round(query_time, 2),
                "sources_queried": len(results),
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "version": "2.2"
            }
        }
        
        logger.info(f"[ANALYSIS COMPLETE] Total time: {time.time() - start_time:.2f}s")
        
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
    
    logger.info("="*80)
    logger.info("🛡️  Multi-Source Threat Intelligence MCP Server v2.2")
    logger.info("="*80)
    logger.info("Aviation Cybersecurity + Multi-Platform Detection Rules")
    logger.info("Intelligence Sources: 17+")
    logger.info("- VirusTotal (with file upload + community comments)")
    logger.info("- Hybrid Analysis, ANY.RUN, Tria.ge, Threat.Zone")
    logger.info("- AbuseIPDB, Shodan (with C2 detection)")
    logger.info("- AlienVault OTX, Abuse.ch suite")
    logger.info("- C2 Trackers: Daily Malware, JMousqueton, C2Live")
    logger.info("- USOM (Turkish National Threat Intel)")
    logger.info("")
    logger.info("Detection Rules:")
    logger.info("✓ KQL (Microsoft Defender EDR)")
    logger.info("✓ SPL (Splunk)")
    logger.info("✓ SIGMA (Universal SIEM)")
    logger.info("✓ XQL (Cortex XDR)")
    logger.info("✓ YARA (Malware Detection)")
    logger.info("")
    logger.info("Features:")
    logger.info("✓ Normalized IOC Scoring (0-100)")
    logger.info("✓ C2 Infrastructure Detection (80+ signatures)")
    logger.info("✓ Domain Entropy Analysis (DNS Tunneling/DGA)")
    logger.info("✓ MITRE ATT&CK Mapping")
    logger.info("✓ Network IOC Extraction")
    logger.info("✓ Malware Family Identification")
    logger.info("✓ JARM/JA3 Known C2 Database")
    logger.info("✓ VirusTotal Community Intelligence")
    logger.info("="*80)
    
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options()
        )


if __name__ == "__main__":
    asyncio.run(main())


from c2_signatures import (
    C2_FRAMEWORKS, MALWARE_FAMILIES, ATTACK_TOOLS, BOTNETS,
    ALL_MALICIOUS_KEYWORDS, SHODAN_C2_PATTERNS, C2_TRACKER_REPOS,
    C2_SCORING_WEIGHTS, get_malware_category
)


async def query_c2_trackers(session: aiohttp.ClientSession, ioc: str, ioc_type: str) -> Dict:
    """Query C2 tracker repositories for IOC matches"""
    matches = []
    
    try:
        for tracker in C2_TRACKER_REPOS:
            try:
                async with session.get(tracker['url'], timeout=aiohttp.ClientTimeout(total=15)) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Check if IOC is in the tracker
                        if ioc in content:
                            matches.append({
                                'tracker': tracker['name'],
                                'url': tracker['url'],
                                'type': tracker['type'],
                                'matched': True
                            })
                            logger.info(f"[C2-TRACKER] {ioc} found in {tracker['name']}")
            except Exception as e:
                logger.warning(f"[C2-TRACKER] {tracker['name']} query failed: {e}")
                continue
        
        if matches:
            return {
                "source": "C2-Trackers",
                "matches": matches,
                "total_trackers_matched": len(matches),
                "status": "CONFIRMED_C2_INFRASTRUCTURE"
            }
        else:
            return {"status": "not_found"}
            
    except Exception as e:
        logger.error(f"C2 tracker query error: {e}")
        return {"error": str(e)}


def detect_c2_malware_keywords(text: str) -> List[Dict]:
    """Detect C2/Malware keywords in text (e.g., Shodan data)"""
    detections = []
    text_lower = text.lower()
    
    for keyword in ALL_MALICIOUS_KEYWORDS:
        if keyword.lower() in text_lower:
            category = get_malware_category(keyword)
            detections.append({
                'keyword': keyword,
                'category': category,
                'context': 'Shodan/Banner'
            })
    
    return detections


async def enhanced_shodan_c2_detection(session: aiohttp.ClientSession, ip: str, shodan_data: Dict) -> Dict:
    """Enhanced Shodan analysis with C2 keyword detection"""
    c2_indicators = {
        'is_likely_c2': False,
        'c2_keywords': [],
        'c2_patterns': [],
        'confidence': 'low'
    }
    
    if not shodan_data or 'error' in shodan_data:
        return c2_indicators
    
    # Check banners, products, and services for C2 keywords
    search_text = json.dumps(shodan_data).lower()
    
    # Detect keywords
    keyword_matches = detect_c2_malware_keywords(search_text)
    if keyword_matches:
        c2_indicators['c2_keywords'] = keyword_matches
        c2_indicators['is_likely_c2'] = True
        
        # Determine confidence based on number of matches
        if len(keyword_matches) >= 3:
            c2_indicators['confidence'] = 'high'
        elif len(keyword_matches) >= 2:
            c2_indicators['confidence'] = 'medium'
        else:
            c2_indicators['confidence'] = 'low'
    
    # Check for known C2 patterns in Shodan
    for c2_name, patterns in SHODAN_C2_PATTERNS.items():
        for pattern in patterns:
            if pattern.lower().replace('product:', '').replace('http.title:', '') in search_text:
                c2_indicators['c2_patterns'].append({
                    'c2_framework': c2_name,
                    'pattern': pattern
                })
                c2_indicators['is_likely_c2'] = True
    
    return c2_indicators



# ==================== USOM (Turkish National Threat Intel) ====================

async def query_usom_malicious_list(session: aiohttp.ClientSession, ioc: str, ioc_type: str) -> Dict:
    """Query USOM Turkish national threat intelligence database"""
    if ioc_type not in ['ip', 'domain', 'url']:
        return {"status": "not_applicable"}
    
    try:
        async with session.get('https://www.usom.gov.tr/url-list.txt',
                              timeout=aiohttp.ClientTimeout(total=10)) as response:
            if response.status == 200:
                content = await response.text()
                
                # Check if IOC exists in USOM list
                if ioc in content:
                    return {
                        "source": "USOM-Turkey",
                        "status": "LISTED_AS_MALICIOUS",
                        "list_type": "National Threat Database",
                        "country": "TR",
                        "description": "Found in Turkish National Cyber Incident Response Center (USOM) malicious list"
                    }
        
        return {"status": "not_found"}
        
    except Exception as e:
        logger.error(f"USOM query error: {e}")
        return {"error": str(e)}


# ==================== DOMAIN ENTROPY ANALYSIS ====================

def analyze_domain_entropy(domain: str) -> Dict:
    """Analyze domain for suspicious patterns (DNS tunneling, DGA, etc.)"""
    import math
    from collections import Counter
    
    # Extract subdomain (first part before first dot)
    parts = domain.split('.')
    if len(parts) < 2:
        return {"is_suspicious": False, "reason": "Invalid domain format"}
    
    subdomain = parts[0]
    
    # Calculate Shannon entropy
    def calculate_entropy(text: str) -> float:
        if not text:
            return 0.0
        counter = Counter(text.lower())
        length = len(text)
        entropy = -sum((count/length) * math.log2(count/length) 
                      for count in counter.values())
        return entropy
    
    entropy = calculate_entropy(subdomain)
    
    # Analysis metrics
    length = len(subdomain)
    has_numbers = any(c.isdigit() for c in subdomain)
    has_hyphens = '-' in subdomain
    
    # Detect patterns
    is_long = length > 50  # DNS tunneling often uses long subdomains
    high_entropy = entropy > 3.5  # Normal domains: 2.5-3.0, random: >3.5
    very_high_entropy = entropy > 4.0
    
    # Base32/Base64 pattern detection
    import re
    is_base32 = bool(re.match(r'^[A-Z2-7]+=*$', subdomain.upper()))
    is_base64_like = bool(re.match(r'^[A-Za-z0-9+/]+=*$', subdomain))
    
    # Verdict
    suspicious_factors = []
    confidence = "low"
    
    if is_long:
        suspicious_factors.append(f"Long subdomain ({length} chars)")
    if high_entropy:
        suspicious_factors.append(f"High entropy ({entropy:.2f})")
    if is_base32:
        suspicious_factors.append("Base32 encoded pattern")
    if is_base64_like and high_entropy:
        suspicious_factors.append("Base64-like pattern")
    
    if len(suspicious_factors) >= 3 or very_high_entropy:
        confidence = "high"
        is_suspicious = True
    elif len(suspicious_factors) >= 2:
        confidence = "medium"
        is_suspicious = True
    elif len(suspicious_factors) == 1:
        is_suspicious = False
    else:
        is_suspicious = False
    
    return {
        "is_suspicious": is_suspicious,
        "confidence": confidence,
        "metrics": {
            "subdomain_length": length,
            "entropy": round(entropy, 2),
            "has_numbers": has_numbers,
            "has_hyphens": has_hyphens,
            "is_base32_encoded": is_base32,
            "is_base64_like": is_base64_like
        },
        "suspicious_factors": suspicious_factors if suspicious_factors else ["None"],
        "verdict": "Possible DNS tunneling or DGA domain" if is_suspicious else "Normal domain pattern"
    }


# ==================== MALWARE FAMILY EXTRACTION ====================

def extract_malware_families(results: Dict) -> List[str]:
    """Extract malware family names from all intelligence sources"""
    families = set()
    
    # VirusTotal
    if 'VirusTotal' in results:
        vt = results['VirusTotal']
        if 'detected_families' in vt:
            families.update(vt['detected_families'])
    
    # Sandbox results
    for sandbox in ['Hybrid-Analysis', 'ANY.RUN', 'Tria.ge', 'Threat.Zone']:
        if sandbox in results:
            data = results[sandbox]
            
            # Family field
            if 'family' in data and data['family'] != 'N/A':
                families.add(data['family'])
            
            # VX family (Hybrid Analysis)
            if 'vx_family' in data and data['vx_family'] != 'N/A':
                families.add(data['vx_family'])
            
            # Malware families list (ANY.RUN)
            if 'malware_families' in data:
                families.update(data['malware_families'])
    
    # Abuse.ch
    if 'Abuse.ch' in results and 'results' in results['Abuse.ch']:
        abuse_results = results['Abuse.ch']['results']
        if 'MalwareBazaar' in abuse_results:
            mb = abuse_results['MalwareBazaar']
            if 'signature' in mb and mb['signature'] != 'N/A':
                families.add(mb['signature'])
    
    return sorted(list(families))


# ==================== IMPORT DETECTION RULE GENERATORS ====================

from detection_rules import (
    generate_spl_queries,
    generate_sigma_rules,
    generate_xql_queries,
    generate_yara_rules
)

