"""
Multi-Platform Detection Rule Generators
Generates ready-to-use detection rules for various SIEM/EDR platforms
"""

from typing import List, Dict
from datetime import datetime


# ==================== SPLUNK SPL GENERATION ====================

def generate_spl_queries(ioc: str, ioc_type: str, severity: str, network_iocs: Dict = None) -> List[str]:
    """Generate Splunk SPL queries"""
    queries = []
    
    if ioc_type == 'ip':
        queries.extend([
            f"""# Splunk: Network connections to malicious IP
index=firewall OR index=proxy OR index=network 
dest_ip="{ioc}" OR dst_ip="{ioc}" OR destination_ip="{ioc}"
| stats count, values(src_ip) as sources, values(dest_port) as ports by dest_ip
| sort -count""",
            
            f"""# Splunk: Timeline of connections
index=* dest_ip="{ioc}"
| timechart span=1h count by src_ip
| sort -_time""",
            
            f"""# Splunk: Identify affected hosts
index=* dest_ip="{ioc}"
| stats count, min(_time) as first_seen, max(_time) as last_seen by host, src_ip
| convert ctime(first_seen) ctime(last_seen)"""
        ])
    
    elif ioc_type == 'domain':
        queries.extend([
            f"""# Splunk: DNS queries to malicious domain
index=dns query="{ioc}" OR domain="{ioc}"
| stats count by src_ip, query
| sort -count""",
            
            f"""# Splunk: Web proxy traffic
index=proxy url="*{ioc}*"
| stats count, values(http_method) as methods, values(uri_path) as paths by src_ip
| sort -count""",
            
            f"""# Splunk: Email with malicious domain
index=email url="*{ioc}*" OR body="*{ioc}*"
| stats count by sender, recipient, subject"""
        ])
    
    elif ioc_type == 'url':
        from urllib.parse import urlparse
        parsed = urlparse(ioc)
        domain = parsed.netloc or parsed.path
        
        queries.extend([
            f"""# Splunk: Exact URL access
index=proxy url="{ioc}"
| stats count, values(http_method) as methods by src_ip, user
| sort -count""",
            
            f"""# Splunk: Domain-based search
index=* domain="{domain}" OR url="*{domain}*"
| stats count by index, sourcetype, src_ip"""
        ])
    
    elif 'hash' in ioc_type:
        hash_field = ioc_type.split('_')[1].upper()
        queries.extend([
            f"""# Splunk: File hash detection
index=endpoint {hash_field}="{ioc}" OR file_hash="{ioc}"
| stats count by host, file_path, file_name, process_name
| sort -count""",
            
            f"""# Splunk: Process execution by hash
index=* process_{hash_field}="{ioc}"
| stats count, values(process_name) as processes, values(parent_process) as parents by host
| sort -count"""
        ])
    
    # Related IOCs from sandbox
    if network_iocs and network_iocs.get('total_iocs', 0) > 0:
        if network_iocs.get('ips'):
            ip_list = ' OR '.join([f'dest_ip="{ip}"' for ip in network_iocs['ips'][:10]])
            queries.append(f"""# Splunk: Hunt for related C2 IPs from sandbox
index=* ({ip_list})
| stats count by dest_ip, src_ip, dest_port
| sort -count""")
    
    # Critical severity - comprehensive hunt
    if severity in ["CRITICAL", "HIGH"]:
        queries.append(f"""# Splunk: 30-day comprehensive hunt
index=* "{ioc}"
| stats count, values(sourcetype) as sources, dc(host) as affected_hosts by index
| sort -count""")
    
    return queries


# ==================== SIGMA RULE GENERATION ====================

def generate_sigma_rules(ioc: str, ioc_type: str, severity: str, score_data: Dict, malware_family: str = None) -> List[str]:
    """Generate SIGMA rules (SIEM-agnostic)"""
    rules = []
    
    # Convert severity to SIGMA level
    sigma_level = {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
        "MINIMAL": "informational"
    }.get(severity, "medium")
    
    timestamp = datetime.utcnow().strftime("%Y/%m/%d")
    
    if ioc_type == 'ip':
        rule = f"""title: Malicious IP Communication Detected - {ioc}
id: {generate_uuid()}
status: experimental
description: Detects network communication to known malicious IP {ioc}
references:
    - Internal Threat Intelligence
    - IOC Score: {score_data['final_score']}/100
author: MCP Threat Intelligence Server
date: {timestamp}
tags:
    - attack.command_and_control
    - attack.t1071
logsource:
    category: network_connection
    product: firewall
detection:
    selection:
        dst_ip: '{ioc}'
    condition: selection
falsepositives:
    - Legitimate connections (validate context)
level: {sigma_level}"""
        rules.append(rule)
        
        # Proxy-specific rule
        rule = f"""title: Malicious IP Access via Proxy - {ioc}
id: {generate_uuid()}
status: experimental
description: Detects proxy traffic to malicious IP {ioc}
author: MCP Threat Intelligence Server
date: {timestamp}
tags:
    - attack.command_and_control
logsource:
    category: proxy
detection:
    selection:
        c-ip: '{ioc}'
    condition: selection
level: {sigma_level}"""
        rules.append(rule)
    
    elif ioc_type == 'domain':
        rule = f"""title: Malicious Domain Access - {ioc}
id: {generate_uuid()}
status: experimental
description: Detects DNS queries or connections to malicious domain {ioc}
references:
    - IOC Score: {score_data['final_score']}/100
author: MCP Threat Intelligence Server
date: {timestamp}
tags:
    - attack.command_and_control
    - attack.t1071.001
logsource:
    category: dns_query
detection:
    selection:
        query: '{ioc}'
    condition: selection
falsepositives:
    - Legitimate domain usage
level: {sigma_level}"""
        rules.append(rule)
    
    elif 'hash' in ioc_type:
        hash_type = ioc_type.split('_')[1].upper()
        malware_tag = f" - {malware_family}" if malware_family else ""
        
        rule = f"""title: Malicious File Execution{malware_tag} - {hash_type}
id: {generate_uuid()}
status: experimental
description: Detects execution of malicious file with {hash_type} hash {ioc}
references:
    - IOC Score: {score_data['final_score']}/100{f'''
    - Malware Family: {malware_family}''' if malware_family else ''}
author: MCP Threat Intelligence Server
date: {timestamp}
tags:
    - attack.execution
    - attack.t1204
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Hashes|contains: '{ioc}'
    condition: selection
falsepositives:
    - Unknown
level: {sigma_level}"""
        rules.append(rule)
        
        # File creation rule
        rule = f"""title: Malicious File Written to Disk{malware_tag}
id: {generate_uuid()}
status: experimental
description: Detects malicious file {hash_type} hash {ioc} written to disk
author: MCP Threat Intelligence Server
date: {timestamp}
tags:
    - attack.defense_evasion
logsource:
    category: file_event
    product: windows
detection:
    selection:
        {hash_type}: '{ioc}'
    condition: selection
level: {sigma_level}"""
        rules.append(rule)
    
    return rules


# ==================== CORTEX XQL GENERATION ====================

def generate_xql_queries(ioc: str, ioc_type: str, severity: str, network_iocs: Dict = None) -> List[str]:
    """Generate Cortex XDR XQL queries"""
    queries = []
    
    if ioc_type == 'ip':
        queries.extend([
            f"""// Cortex XDR: Network connections to malicious IP
dataset = xdr_data
| filter event_type = NETWORK and action_remote_ip = "{ioc}"
| fields _time, agent_hostname, agent_ip_addresses, action_remote_port, action_app_id_transitions
| sort asc _time""",
            
            f"""// Cortex XDR: Process creating network connection
dataset = xdr_data
| filter event_type = NETWORK and action_remote_ip = "{ioc}"
| fields agent_hostname, actor_process_image_name, actor_process_command_line, action_remote_port
| comp count() as connection_count by agent_hostname, actor_process_image_name""",
            
            f"""// Cortex XDR: Timeline analysis
dataset = xdr_data
| filter action_remote_ip = "{ioc}"
| alter hour = bin(_time, 3600000)
| comp count() as events by hour, agent_hostname"""
        ])
    
    elif ioc_type == 'domain':
        queries.extend([
            f"""// Cortex XDR: DNS queries to malicious domain
dataset = xdr_data
| filter event_type = NETWORK and dns_query_name = "{ioc}"
| fields _time, agent_hostname, agent_ip_addresses, dns_query_name
| sort asc _time""",
            
            f"""// Cortex XDR: HTTP/HTTPS connections
dataset = xdr_data
| filter action_remote_url contains "{ioc}"
| fields _time, agent_hostname, actor_process_image_name, action_remote_url, action_remote_ip""",
            
            f"""// Cortex XDR: Affected endpoints
dataset = xdr_data
| filter dns_query_name = "{ioc}" or action_remote_url contains "{ioc}"
| comp count() as event_count, min(_time) as first_seen, max(_time) as last_seen by agent_hostname
| sort desc event_count"""
        ])
    
    elif 'hash' in ioc_type:
        hash_field_map = {
            'md5': 'action_file_md5',
            'sha1': 'action_file_sha1', 
            'sha256': 'action_file_sha256'
        }
        hash_type = ioc_type.split('_')[1]
        hash_field = hash_field_map.get(hash_type, 'action_file_sha256')
        
        queries.extend([
            f"""// Cortex XDR: File hash detection
dataset = xdr_data
| filter {hash_field} = "{ioc}"
| fields _time, agent_hostname, action_file_path, action_file_name, actor_process_image_name
| sort asc _time""",
            
            f"""// Cortex XDR: Process execution
dataset = xdr_data
| filter event_type = PROCESS and {hash_field} = "{ioc}"
| fields _time, agent_hostname, actor_process_image_name, actor_process_command_line, actor_primary_username
| sort asc _time""",
            
            f"""// Cortex XDR: File operations
dataset = xdr_data
| filter {hash_field} = "{ioc}"
| comp count() as operations by agent_hostname, event_sub_type, action_file_path
| sort desc operations"""
        ])
    
    # Related IOCs
    if network_iocs and network_iocs.get('ips'):
        ip_conditions = ' or '.join([f'action_remote_ip = "{ip}"' for ip in network_iocs['ips'][:10]])
        queries.append(f"""// Cortex XDR: Hunt for related C2 IPs
dataset = xdr_data
| filter {ip_conditions}
| comp count() as connections by action_remote_ip, agent_hostname, actor_process_image_name
| sort desc connections""")
    
    # Critical hunt
    if severity in ["CRITICAL", "HIGH"]:
        queries.append(f"""// Cortex XDR: 30-day comprehensive search
dataset = xdr_data
| filter _time > current_time() - 2592000000
| filter action_remote_ip = "{ioc}" or dns_query_name = "{ioc}" or {hash_field} = "{ioc}"
| comp count() as events, dc(agent_hostname) as unique_hosts by event_type
| sort desc events""")
    
    return queries


# ==================== YARA RULE GENERATION ====================

def generate_yara_rules(ioc: str, ioc_type: str, severity: str, malware_family: str = None, network_iocs: Dict = None) -> List[str]:
    """Generate YARA rules for malware detection"""
    rules = []
    
    rule_name = f"MaliciousIOC_{ioc_type}_{ioc[:16].replace('.', '_').replace(':', '_')}"
    family_tag = f' - {malware_family}' if malware_family else ''
    
    if 'hash' in ioc_type:
        hash_type = ioc_type.split('_')[1].upper()
        
        rule = f"""rule {rule_name}{family_tag.replace(' ', '_').replace('-', '')} {{
    meta:
        description = "Detects malicious file by {hash_type} hash{family_tag}"
        author = "MCP Threat Intelligence Server"
        date = "{datetime.utcnow().strftime('%Y-%m-%d')}"
        hash_{hash_type.lower()} = "{ioc}"
        severity = "{severity}"
        ioc_score = "{score_data.get('final_score', 0)}/100"
        {f'malware_family = "{malware_family}"' if malware_family else ''}
        
    condition:
        hash.{hash_type.lower()}(0, filesize) == "{ioc}"
}}"""
        rules.append(rule)
        
        # Memory-based rule
        if malware_family:
            rule = f"""rule {rule_name}_Memory {{
    meta:
        description = "Detects {malware_family} in memory"
        author = "MCP Threat Intelligence Server"
        date = "{datetime.utcnow().strftime('%Y-%m-%d')}"
        
    strings:
        $hash = "{ioc}" ascii wide
        
    condition:
        $hash
}}"""
            rules.append(rule)
    
    elif ioc_type == 'ip':
        rule = f"""rule C2_Communication_{ioc.replace('.', '_')} {{
    meta:
        description = "Detects C2 IP address in strings{family_tag}"
        author = "MCP Threat Intelligence Server"
        date = "{datetime.utcnow().strftime('%Y-%m-%d')}"
        c2_ip = "{ioc}"
        severity = "{severity}"
        
    strings:
        $ip = "{ioc}" ascii wide
        
    condition:
        $ip
}}"""
        rules.append(rule)
        
        # Network IOCs rule
        if network_iocs and network_iocs.get('ips'):
            ip_strings = '\n        '.join([f'$ip{i} = "{ip}" ascii wide' 
                                            for i, ip in enumerate(network_iocs['ips'][:10])])
            
            rule = f"""rule C2_Network_Infrastructure {{
    meta:
        description = "Detects related C2 infrastructure IPs"
        author = "MCP Threat Intelligence Server"
        date = "{datetime.utcnow().strftime('%Y-%m-%d')}"
        primary_c2 = "{ioc}"
        
    strings:
        {ip_strings}
        
    condition:
        any of ($ip*)
}}"""
            rules.append(rule)
    
    elif ioc_type == 'domain':
        rule = f"""rule C2_Domain_{ioc.replace('.', '_').replace('-', '_')} {{
    meta:
        description = "Detects C2 domain in strings{family_tag}"
        author = "MCP Threat Intelligence Server"
        date = "{datetime.utcnow().strftime('%Y-%m-%d')}"
        c2_domain = "{ioc}"
        severity = "{severity}"
        
    strings:
        $domain = "{ioc}" ascii wide nocase
        $http = "http://{ioc}" ascii wide nocase
        $https = "https://{ioc}" ascii wide nocase
        
    condition:
        any of them
}}"""
        rules.append(rule)
    
    return rules


# ==================== HELPER FUNCTIONS ====================

def generate_uuid() -> str:
    """Generate UUID for SIGMA rules"""
    import uuid
    return str(uuid.uuid4())


# Global score_data for YARA rules
score_data = {}
