"""
C2 Server and Malware Signatures Database
Used for enhanced detection and scoring
"""

# C2 Frameworks
C2_FRAMEWORKS = [
    'Cobalt Strike',
    'Metasploit Framework',
    'Covenant',
    'Mythic',
    'Brute Ratel C4',
    'Posh',
    'Sliver',
    'Deimos',
    'PANDA',
    'NimPlant C2',
    'Havoc C2',
    'Caldera',
    'Empire',
    'Ares',
    'Hak5 Cloud C2',
    'Pantegana',
    'Supershell',
    'Vshell',
    'Villain',
    'Nimplant C2',
    'RedGuard C2',
    'Oyster C2',
    'byob C2'
]

# Malware Families
MALWARE_FAMILIES = [
    # Stealers
    'AcidRain Stealer',
    'Misha Stealer',
    'Grand Misha',
    'Patriot Stealer',
    'RAXNET Bitcoin Stealer',
    'Titan Stealer',
    'Collector Stealer',
    'Mystic Stealer',
    'Gotham Stealer',
    'Meduza Stealer',
    'RisePro Stealer',
    'Bandit Stealer',
    'Mint Stealer',
    'Atlandida Stealer',
    'Atomic Stealer',
    'Lumma Stealer',
    'Serpent Stealer',
    'Axile Stealer',
    'Vector Stealer',
    'Z3us Stealer',
    'Rastro Stealer',
    'Darkeye Stealer',
    'Agniane Stealer',
    'Epsilon Stealer',
    'Bahamut Stealer',
    'Vidar Stealer',
    'Spectre Stealer',
    
    # RATs
    'Quasar RAT',
    'ShadowPad',
    'AsyncRAT',
    'DcRat',
    'BitRAT',
    'DarkComet Trojan',
    'XtremeRAT Trojan',
    'NanoCore RAT Trojan',
    'Gh0st RAT Trojan',
    'DarkTrack RAT Trojan',
    'njRAT Trojan',
    'Remcos Pro RAT Trojan',
    'Poison Ivy Trojan',
    'Orcus RAT Trojan',
    'VenomRAT',
    'BlackDolphin',
    'Artemis RAT',
    'SpyAgent',
    'SpiceRAT',
    'Dust RAT',
    'Pupy RAT',
    'Kraken RAT',
    'Viper RAT',
    'Sectop RAT',
    
    # Trojans
    'ZeroAccess Trojan',
    'HOOKBOT Trojan',
    'NetBus Trojan',
    'Mekotio Trojan',
    'Gozi Trojan',
    
    # Loaders
    'Godzilla Loader',
    'Jinx Loader',
    'Netpune Loader',
    'Bumblebee Loader'
]

# Pentesting/Attack Tools
ATTACK_TOOLS = [
    'XMRig Monero Cryptominer',
    'GoPhish',
    'Browser Exploitation Framework',
    'BeEF',
    'BurpSuite',
    'Hashcat',
    'MobSF',
    'EvilGoPhish',
    'EvilGinx',
    'Unam Web Panel',
    'SilentCryptoMiner'
]

# Botnets
BOTNETS = [
    '7777',
    'BlackNET',
    'Doxerina',
    'Scarab',
    '63256',
    'Kaiji',
    'MooBot',
    'Mozi'
]

# Combined keyword list for detection
ALL_MALICIOUS_KEYWORDS = (
    C2_FRAMEWORKS + 
    MALWARE_FAMILIES + 
    ATTACK_TOOLS + 
    BOTNETS
)

# Shodan search patterns for C2 detection
SHODAN_C2_PATTERNS = {
    'Cobalt Strike': ['product:"cobalt strike"', 'ssl.cert.subject.CN:"Major Cobalt Strike"'],
    'Metasploit': ['product:metasploit', 'http.title:"metasploit"'],
    'Sliver': ['product:sliver', 'ssl.cert.issuer.CN:sliver'],
    'Mythic': ['product:mythic'],
    'Covenant': ['http.title:covenant'],
    'Brute Ratel': ['product:"brute ratel"'],
    'Empire': ['http.html:"Empire"'],
    'Havoc': ['product:havoc'],
    'GoPhish': ['product:gophish', 'http.title:gophish'],
    'XMRig': ['product:xmrig', 'http.html:"XMRig"']
}

# C2 GitHub Trackers
C2_TRACKER_REPOS = [
    {
        'name': 'Daily Dose of Malware',
        'url': 'https://raw.githubusercontent.com/Titokhan/Daily-dose-of-malware/main/IOCs.txt',
        'type': 'IOC_LIST'
    },
    {
        'name': 'JMousqueton C2-Tracker',
        'url': 'https://raw.githubusercontent.com/JMousqueton/C2-Tracker/main/data/all.txt',
        'type': 'IP_LIST'
    },
    {
        'name': 'C2Live',
        'url': 'https://raw.githubusercontent.com/YoNixNeXRo/C2Live/main/c2_ips.txt',
        'type': 'IP_LIST'
    }
]

# Scoring weights for C2/Malware detection
C2_SCORING_WEIGHTS = {
    'c2_framework_detected': 35,      # High score for C2 framework detection
    'malware_family_detected': 30,     # High score for known malware
    'attack_tool_detected': 25,        # Pentesting/attack tools
    'botnet_detected': 40,             # Very high for botnet infrastructure
    'c2_tracker_match': 30,            # Found in C2 tracker databases
    'shodan_c2_pattern': 35            # Shodan detects C2 pattern
}

def get_malware_category(keyword: str) -> str:
    """Determine malware category"""
    keyword_lower = keyword.lower()
    
    if any(k.lower() in keyword_lower for k in C2_FRAMEWORKS):
        return 'C2 Framework'
    elif any(k.lower() in keyword_lower for k in MALWARE_FAMILIES):
        if 'stealer' in keyword_lower:
            return 'Information Stealer'
        elif 'rat' in keyword_lower or 'trojan' in keyword_lower:
            return 'Remote Access Trojan'
        elif 'loader' in keyword_lower:
            return 'Malware Loader'
        else:
            return 'Malware'
    elif any(k.lower() in keyword_lower for k in ATTACK_TOOLS):
        return 'Attack Tool'
    elif any(k.lower() in keyword_lower for k in BOTNETS):
        return 'Botnet'
    
    return 'Unknown'


# ==================== JARM/JA3 KNOWN C2 DATABASE ====================

KNOWN_C2_JARM_HASHES = {
    # Cobalt Strike
    '2ad2ad16d2ad2ad00042d42d00042ddb04deffa1705e2edc44cae1ed24a4da': {
        'framework': 'Cobalt Strike',
        'version': 'Default',
        'confidence': 'high'
    },
    '2ad2ad0002ad2ad00042d42d00000ad9bf51cc3f5a1e29eecb81d0c7b06eb': {
        'framework': 'Cobalt Strike',
        'version': '4.x',
        'confidence': 'high'
    },
    
    # Metasploit
    '07d14d16d21d21d00042d41d00041de5fb3038104f457d92ba02e9311512c2': {
        'framework': 'Metasploit',
        'version': 'Default',
        'confidence': 'high'
    },
    '07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1': {
        'framework': 'Metasploit',
        'version': '6.x',
        'confidence': 'medium'
    },
    
    # Sliver
    '00000000000000000041d00000041d9535d5979f591ae8e547c5e5743e5b64': {
        'framework': 'Sliver',
        'version': 'Default Go',
        'confidence': 'high'
    },
    
    # Empire
    '27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d': {
        'framework': 'PowerShell Empire',
        'version': 'Default',
        'confidence': 'medium'
    },
    
    # Covenant
    '29d29d00029d29d00042d43d00041d598ac0c1012db967bb1ad0ff2491b3ae': {
        'framework': 'Covenant',
        'version': '.NET',
        'confidence': 'medium'
    },
    
    # Mythic
    '2ad2ad16d2ad2ad22c42d42d00042d9eebd93c980f9caa36b7d76f240f7f01': {
        'framework': 'Mythic',
        'version': 'Default',
        'confidence': 'medium'
    },
    
    # Brute Ratel
    '3fd3fd00000000000041d3fd00041d3fd41f3fd41f3fd41f3fd0000000000': {
        'framework': 'Brute Ratel C4',
        'version': 'BRC4',
        'confidence': 'high'
    }
}

KNOWN_JA3_HASHES = {
    # Trickbot
    '6734f37431670b3ab4292b8f60f29984': {
        'malware': 'Trickbot',
        'type': 'Banking Trojan',
        'confidence': 'high'
    },
    
    # Emotet
    'e7d705a3286e19ea42f587b344ee6865': {
        'malware': 'Emotet',
        'type': 'Loader',
        'confidence': 'high'
    },
    
    # Cobalt Strike Beacon
    'a0e9f5d64349fb13191bc781f81f42e1': {
        'malware': 'Cobalt Strike Beacon',
        'type': 'C2 Framework',
        'confidence': 'medium'
    }
}


def detect_c2_from_jarm(jarm_hash: str) -> dict:
    """Detect C2 framework from JARM fingerprint"""
    if jarm_hash in KNOWN_C2_JARM_HASHES:
        return {
            'detected': True,
            'source': 'JARM Fingerprint',
            **KNOWN_C2_JARM_HASHES[jarm_hash]
        }
    return {'detected': False}


def detect_malware_from_ja3(ja3_hash: str) -> dict:
    """Detect malware from JA3 fingerprint"""
    if ja3_hash in KNOWN_JA3_HASHES:
        return {
            'detected': True,
            'source': 'JA3 Fingerprint',
            **KNOWN_JA3_HASHES[ja3_hash]
        }
    return {'detected': False}
