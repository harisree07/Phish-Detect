import re
from typing import Set, List

# Unicode homoglyphs mapping (visually similar characters for homoglyph attacks)
HOMOGLYPHS = {
    'a': ['а', 'a', 'à', 'á', 'â', 'ã', 'ä', 'å', 'а', 'a'],
    'c': ['с', 'c', 'ç', 'ć', 'č'],
    'e': ['е', 'e', 'è', 'é', 'ê', 'ë', 'е'],
    'i': ['і', '1', 'l', 'í', 'î', 'ï'],
    'l': ['1', 'i', 'l', 'ł'],
    'o': ['о', '0', 'ò', 'ó', 'ô', 'õ', 'ö', 'ø', 'о'],
    's': ['ѕ', 'ś', 'š', 'ş'],
    'u': ['υ', 'ù', 'ú', 'û', 'ü'],
    'w': ['vv', 'w'],
    'y': ['у', 'ý', 'ÿ', 'у']
}

# Keyboard proximity map (QWERTY layout)
KEYBOARD_PROXIMITY = {
    'a': ['q', 'w', 's', 'z'],
    'b': ['v', 'g', 'h', 'n'],
    'c': ['x', 'd', 'f', 'v'],
    'd': ['s', 'e', 'r', 'f', 'c', 'x'],
    'e': ['w', 's', 'd', 'r'],
    'f': ['d', 'r', 't', 'g', 'v', 'c'],
    'g': ['f', 't', 'y', 'h', 'b', 'v'],
    'h': ['g', 'y', 'u', 'j', 'n', 'b'],
    'i': ['u', 'j', 'k', 'o'],
    'j': ['h', 'u', 'i', 'k', 'm', 'n'],
    'k': ['j', 'i', 'o', 'l', 'm'],
    'l': ['k', 'o', 'p'],
    'm': ['n', 'j', 'k'],
    'n': ['b', 'h', 'j', 'm'],
    'o': ['i', 'k', 'l', 'p'],
    'p': ['o', 'l'],
    'q': ['1', '2', 'w', 'a'],
    'r': ['e', 'd', 'f', 't'],
    's': ['a', 'w', 'e', 'd', 'x', 'z'],
    't': ['r', 'f', 'g', 'y'],
    'u': ['y', 'h', 'j', 'i'],
    'v': ['c', 'f', 'g', 'b'],
    'w': ['q', 'a', 's', 'e'],
    'x': ['z', 's', 'd', 'c'],
    'y': ['t', 'g', 'h', 'u'],
    'z': ['a', 's', 'x']
}

# Common keywords used in phishing attacks
PHISHING_KEYWORDS = [
    "login", "signin", "support", "secure", "security", "verify",
    "account", "billing", "update", "portal", "help", "service",
    "admin", "payment", "bank", "office", "mail"
]

# Alternate TLDs frequently used for typosquatting/phishing
POPULAR_TLDS = [
    "com", "net", "org", "co", "info", "biz", "xyz", "top", "club",
    "online", "site", "tech", "cc", "io", "ru", "su", "cn", "link", "click"
]

class DomainGenerator:
    """
    Generates variations of a target domain to identify potential typosquatting 
    and phishing targets.
    """
    
    def __init__(self, target_domain: str):
        self.target_domain = target_domain.lower().strip()
        self.domain_name, self.tld = self._split_domain()
        
    def _split_domain(self) -> tuple[str, str]:
        """Splits domain into name and TLD parts (e.g. google.com -> google, com)"""
        parts = self.target_domain.split('.')
        if len(parts) > 1:
            return parts[0], '.'.join(parts[1:])
        return self.target_domain, "com"
        
    def generate(self, max_domains: int = 500) -> List[str]:
        """
        Generates permutation list.
        
        Args:
            max_domains (int): Cap on generated domains. 0 for unlimited.
            
        Returns:
            List[str]: List of unique generated domain strings.
        """
        variations: Set[str] = set()
        
        # 1. Missing letters (omission)
        for i in range(len(self.domain_name)):
            omitted = self.domain_name[:i] + self.domain_name[i+1:]
            if omitted:
                variations.add(f"{omitted}.{self.tld}")
                
        # 2. Extra letters (repetition)
        for i in range(len(self.domain_name)):
            repeated = self.domain_name[:i] + self.domain_name[i] + self.domain_name[i:]
            variations.add(f"{repeated}.{self.tld}")
            
        # 3. Swapped adjacent characters (transposition)
        for i in range(len(self.domain_name) - 1):
            char_list = list(self.domain_name)
            char_list[i], char_list[i+1] = char_list[i+1], char_list[i]
            swapped = "".join(char_list)
            variations.add(f"{swapped}.{self.tld}")
            
        # 4. Keyboard proximity substitutions
        for i, char in enumerate(self.domain_name):
            if char in KEYBOARD_PROXIMITY:
                for close_char in KEYBOARD_PROXIMITY[char]:
                    substituted = self.domain_name[:i] + close_char + self.domain_name[i+1:]
                    variations.add(f"{substituted}.{self.tld}")
                    
        # 5. Homoglyphs (visually similar Unicode substitutes)
        for i, char in enumerate(self.domain_name):
            if char in HOMOGLYPHS:
                for glyph in HOMOGLYPHS[char]:
                    glyph_name = self.domain_name[:i] + glyph + self.domain_name[i+1:]
                    # Convert to Punycode/IDNA domain for proper DNS/WHOIS resolution
                    try:
                        idna_encoded = glyph_name.encode('idna').decode('ascii')
                        variations.add(f"{idna_encoded}.{self.tld}")
                    except Exception:
                        pass
                        
        # 6. Hyphen insertion
        for i in range(1, len(self.domain_name)):
            hyphenated = f"{self.domain_name[:i]}-{self.domain_name[i:]}"
            variations.add(f"{hyphenated}.{self.tld}")
            
        # 7. Brand keyword additions (prefixes and suffixes with hyphens)
        for kw in PHISHING_KEYWORDS:
            variations.add(f"{self.domain_name}-{kw}.{self.tld}")
            variations.add(f"{kw}-{self.domain_name}.{self.tld}")
            variations.add(f"{self.domain_name}{kw}.{self.tld}")
            variations.add(f"{kw}{self.domain_name}.{self.tld}")
            
        # 8. TLD Swapping
        for alt_tld in POPULAR_TLDS:
            if alt_tld != self.tld:
                variations.add(f"{self.domain_name}.{alt_tld}")
                
        # Remove target domain if generated
        if self.target_domain in variations:
            variations.remove(self.target_domain)
            
        # Filter valid domains only
        valid_variations = [d for d in variations if self._is_valid_domain(d)]
        
        # Limit count if requested
        if max_domains > 0:
            return sorted(valid_variations)[:max_domains]
        return sorted(valid_variations)
        
    def _is_valid_domain(self, domain: str) -> bool:
        """Simple regex validation to ensure the generated string conforms to standard domain syntax."""
        pattern = r'^([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,18}$'
        return bool(re.match(pattern, domain))
