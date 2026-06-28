import whois
from datetime import datetime
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger("phish_detect.whois")

class WhoisChecker:
    """
    Checks WHOIS registration details for target domains.
    Handles dates normalization, registrar, and organization extraction.
    """
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        
    def check_domain(self, domain: str) -> Dict[str, Any]:
        """
        Queries WHOIS data for a domain.
        
        Args:
            domain (str): Domain name to query.
            
        Returns:
            Dict[str, Any]: Dict containing registration status and attributes:
                - registered (bool)
                - creation_date (datetime or None)
                - expiration_date (datetime or None)
                - registrar (str or None)
                - organization (str or None)
                - country (str or None)
                - nameservers (list or None)
                - raw (str or None)
        """
        result = {
            "registered": False,
            "creation_date": None,
            "expiration_date": None,
            "registrar": None,
            "organization": None,
            "country": None,
            "nameservers": None,
            "raw": None
        }
        
        # Punycode domains should be checked by their ascii representation
        try:
            ascii_domain = domain.encode('idna').decode('ascii')
        except Exception:
            ascii_domain = domain
            
        try:
            # whois.whois makes socket connections to registry/registrar whois servers
            logger.debug(f"Querying WHOIS for {ascii_domain}")
            w = whois.whois(ascii_domain)
            
            # If domain has no creation date or registrar, it usually means it's not registered
            # but we also check if 'domain_name' or another field is populated
            if not w or not w.domain_name:
                logger.debug(f"No WHOIS details found for {ascii_domain}. Assumed unregistered.")
                return result
                
            result["registered"] = True
            result["registrar"] = self._normalize_string(w.registrar)
            result["organization"] = self._normalize_string(w.org or w.registrant_postal_patron_of_record_name)
            result["country"] = self._normalize_string(w.country)
            
            # Normalizing creation date
            result["creation_date"] = self._parse_date(w.creation_date)
            result["expiration_date"] = self._parse_date(w.expiration_date)
            
            # Normalizing nameservers
            if w.name_servers:
                if isinstance(w.name_servers, list):
                    result["nameservers"] = [str(ns).lower() for ns in w.name_servers]
                else:
                    result["nameservers"] = [str(w.name_servers).lower()]
                    
            result["raw"] = str(w)
            
        except Exception as e:
            err_msg = str(e).lower()
            err_class = type(e).__name__.lower()
            if "no match" in err_msg or "not found" in err_msg or "no data found" in err_msg or "pywhoiserror" in err_class:
                logger.debug(f"Domain {ascii_domain} not registered or lookup error: {e}")
            elif any(x in err_class or x in err_msg for x in ["connectionreset", "timeout", "forcibly closed", "socket"]):
                logger.warning(f"WHOIS check for {ascii_domain} failed due to rate-limiting or connection reset.")
            else:
                logger.error(f"Error checking WHOIS for {ascii_domain}: {e}", exc_info=True)
            
        return result
        
    def _normalize_string(self, val: Any) -> Optional[str]:
        """Ensures the value is parsed as string or None, removing whitespace."""
        if val is None:
            return None
        if isinstance(val, list):
            # Take the first element of list if multiple values exist
            val = val[0] if val else ""
        s = str(val).strip()
        return s if s else None
        
    def _parse_date(self, date_val: Any) -> Optional[datetime]:
        """Normalizes dates which can be single datetime, list of datetimes, or strings."""
        if date_val is None:
            return None
        if isinstance(date_val, list):
            date_val = date_val[0]
            
        if isinstance(date_val, datetime):
            return date_val
            
        # Parse from string if necessary
        if isinstance(date_val, str):
            for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%d-%b-%Y", "%Y/%m/%d"):
                try:
                    return datetime.strptime(date_val.split(".")[0].split("Z")[0], fmt)
                except ValueError:
                    continue
        return None
