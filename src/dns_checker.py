import dns.resolver
from typing import Dict, Any, List
import logging

logger = logging.getLogger("phish_detect.dns")

class DnsChecker:
    """
    Retrieves and inspects DNS records (A, AAAA, MX, NS, TXT, CNAME) for target domains.
    Detects resolution status and flags suspicious structures.
    """
    
    def __init__(self, timeout: int = 10):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = float(timeout)
        self.resolver.lifetime = float(timeout)
        
    def resolve_all(self, domain: str) -> Dict[str, Any]:
        """
        Performs DNS queries for common records.
        
        Args:
            domain (str): Domain to resolve.
            
        Returns:
            Dict[str, Any]: Dict containing record types and resolutions:
                - resolves (bool)
                - a_records (list of str)
                - aaaa_records (list of str)
                - mx_records (list of str)
                - ns_records (list of str)
                - txt_records (list of str)
                - cname_records (list of str)
                - flags (list of str)
        """
        results = {
            "resolves": False,
            "a_records": [],
            "aaaa_records": [],
            "mx_records": [],
            "ns_records": [],
            "txt_records": [],
            "cname_records": [],
            "flags": []
        }
        
        # Punycode encoding
        try:
            ascii_domain = domain.encode('idna').decode('ascii')
        except Exception:
            ascii_domain = domain
            
        # 1. Check A records (IPv4 resolution)
        results["a_records"] = self._query_record(ascii_domain, "A")
        if results["a_records"]:
            results["resolves"] = True
            
        # 2. Check AAAA records (IPv6 resolution)
        results["aaaa_records"] = self._query_record(ascii_domain, "AAAA")
        if results["aaaa_records"]:
            results["resolves"] = True
            
        # If the domain doesn't resolve to IPv4 or IPv6, check if CNAME is configured
        results["cname_records"] = self._query_record(ascii_domain, "CNAME")
        if results["cname_records"]:
            results["resolves"] = True
            
        # Only query other records if there is some resolution to save network cycles
        if results["resolves"]:
            results["mx_records"] = self._query_record(ascii_domain, "MX")
            results["ns_records"] = self._query_record(ascii_domain, "NS")
            results["txt_records"] = self._query_record(ascii_domain, "TXT")
            
            # Analyze findings for suspicious DNS anomalies
            self._analyze_anomalies(results)
            
        return results
        
    def _query_record(self, domain: str, rtype: str) -> List[str]:
        """Queries a specific record type and returns strings list."""
        try:
            answers = self.resolver.resolve(domain, rtype)
            records = []
            for rdata in answers:
                if rtype == "MX":
                    # MX returns (preference, exchange)
                    records.append(f"{rdata.preference} {rdata.exchange.to_text().rstrip('.')}")
                elif rtype == "TXT":
                    # TXT contains strings, concatenate them
                    records.append("".join([s.decode('utf-8', errors='ignore') for s in rdata.strings]))
                else:
                    records.append(rdata.to_text().rstrip('.'))
            return records
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout, dns.resolver.NoNameservers):
            return []
        except Exception as e:
            logger.debug(f"DNS {rtype} lookup error for {domain}: {e}")
            return []
            
    def _analyze_anomalies(self, results: Dict[str, Any]) -> None:
        """Flags suspicious DNS configurations typical of phishing domains."""
        # 1. Domain resolves but lacks MX records (frequently typosquatted landing pages don't configure mail)
        # Note: If they want to send phishing mails, they will set up MX. But setting MX is highly suspicious
        # if combined with other triggers. Let's flag both possibilities.
        if results["mx_records"]:
            results["flags"].append("MX record configured (capable of sending/receiving email)")
        else:
            results["flags"].append("No MX record configured (purely web landing page)")
            
        # 2. Suspicious TLD / Hosting check can be added or handled by the risk engine
        # 3. Wildcard NS check
        if len(results["ns_records"]) == 1:
            results["flags"].append("Single Name Server configuration (low redundancy)")
            
        # 4. Check for SPF record issues in TXT
        has_spf = False
        for txt in results["txt_records"]:
            if txt.startswith("v=spf1"):
                has_spf = True
                if "-all" not in txt and "~all" not in txt:
                    results["flags"].append("Weak SPF policy (-all or ~all missing)")
        if results["mx_records"] and not has_spf:
            results["flags"].append("MX records present but no SPF record configured")
