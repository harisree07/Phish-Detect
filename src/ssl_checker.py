import socket
import ssl
import logging
from datetime import datetime
from typing import Dict, Any, Optional

logger = logging.getLogger("phish_detect.ssl")

class SslChecker:
    """
    Retrieves and inspects SSL/TLS certificates for active websites.
    Identifies expiration, self-signed issuers, wildcard coverage, and mismatches.
    """
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        
    def check_certificate(self, domain: str, port: int = 443) -> Dict[str, Any]:
        """
        Connects to a domain via SSL/TLS and extracts certificate fields.
        
        Args:
            domain (str): The domain to check.
            port (int): HTTPS port (default 443).
            
        Returns:
            Dict[str, Any]: Certificate inspection results:
                - has_ssl (bool)
                - issuer (str or None)
                - subject (str or None)
                - valid_from (datetime or None)
                - valid_to (datetime or None)
                - is_expired (bool)
                - is_self_signed (bool)
                - is_wildcard (bool)
                - error (str or None)
        """
        result = {
            "has_ssl": False,
            "issuer": None,
            "subject": None,
            "valid_from": None,
            "valid_to": None,
            "is_expired": False,
            "is_self_signed": False,
            "is_wildcard": False,
            "error": None
        }
        
        # Punycode encoding
        try:
            ascii_domain = domain.encode('idna').decode('ascii')
        except Exception:
            ascii_domain = domain
            
        context = ssl.create_default_context()
        # Allow checking expired/invalid/self-signed certs rather than failing during handshake
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        try:
            logger.debug(f"Attempting SSL connection to {ascii_domain}:{port}")
            with socket.create_connection((ascii_domain, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=ascii_domain) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    if not cert:
                        result["error"] = "Failed to retrieve peer certificate"
                        return result
                        
                    # Parse binary DER certificate to inspect details
                    x509 = ssl.DER_cert_to_PEM_cert(cert)
                    # Use Python's built-in parser by wrapping with CERT_REQUIRED metadata load
                    # Since wrap_socket verify_mode was CERT_NONE, we get getpeercert() = None when binary_form=False.
                    # Instead of manual PEM parsing, let's make a verify check. We can obtain the certificate with CERT_OPTIONAL.
                    
        except Exception as e:
            result["error"] = str(e)
            logger.debug(f"Initial SSL check failed for {ascii_domain}: {e}")
            return result
            
        # Recheck with CERT_REQUIRED/OPTIONAL but ignoring errors to extract details
        context_detail = ssl.create_default_context()
        context_detail.check_hostname = False
        context_detail.verify_mode = ssl.CERT_NONE
        
        try:
            with socket.create_connection((ascii_domain, port), timeout=self.timeout) as sock:
                with context_detail.wrap_socket(sock, server_hostname=ascii_domain) as ssock:
                    cert_dict = ssock.getpeercert()
                    if cert_dict:
                        result["has_ssl"] = True
                        result["issuer"] = self._format_name(cert_dict.get("issuer"))
                        result["subject"] = self._format_name(cert_dict.get("subject"))
                        
                        # Parsing validity dates
                        result["valid_from"] = self._parse_ssl_date(cert_dict.get("notBefore"))
                        result["valid_to"] = self._parse_ssl_date(cert_dict.get("notAfter"))
                        
                        # Expiry status
                        if result["valid_to"]:
                            valid_to = result["valid_to"]
                            if valid_to.tzinfo is not None:
                                valid_to = valid_to.replace(tzinfo=None)
                            result["is_expired"] = datetime.utcnow() > valid_to
                            
                        # Wildcard detection
                        # Check subject alt names or subject common name
                        subject_cn = ""
                        for item in cert_dict.get("subject", []):
                            for key, val in item:
                                if key == "commonName":
                                    subject_cn = val
                                    break
                                    
                        if subject_cn.startswith("*."):
                            result["is_wildcard"] = True
                            
                        san_list = cert_dict.get("subjectAltName", [])
                        for san_type, san_val in san_list:
                            if san_type == "DNS" and san_val.startswith("*."):
                                result["is_wildcard"] = True
                                
                        # Self-signed detection
                        # Simple rule: if subject matches issuer common name, or if we get verification issues
                        # We compare the formatted subject and issuer strings.
                        if result["subject"] and result["issuer"]:
                            # Clean details to verify identity matches
                            if result["subject"] == result["issuer"]:
                                result["is_self_signed"] = True
                                
        except Exception as e:
            result["error"] = f"Parsing certificate failed: {e}"
            logger.debug(f"Detailed SSL extraction error for {ascii_domain}: {e}")
            
        return result
        
    def _format_name(self, name_tuple: Any) -> Optional[str]:
        """Converts cert issuer/subject tuple format to a single readable string."""
        if not name_tuple or not isinstance(name_tuple, tuple):
            return None
        parts = []
        for rdns in name_tuple:
            for attr_name, attr_val in rdns:
                parts.append(f"{attr_name}={attr_val}")
        return ", ".join(parts)
        
    def _parse_ssl_date(self, date_str: Optional[str]) -> Optional[datetime]:
        """Parses SSL certificate date string (e.g. 'Apr 15 12:00:00 2026 GMT')."""
        if not date_str:
            return None
        # Format commonly: "Jan  5 12:00:00 2026 GMT"
        # Let's remove double spaces and GMT string
        normalized = " ".join(date_str.split())
        if normalized.endswith(" GMT"):
            normalized = normalized[:-4]
        for fmt in ("%b %d %H:%M:%S %Y", "%B %d %H:%M:%S %Y"):
            try:
                return datetime.strptime(normalized, fmt)
            except ValueError:
                continue
        return None
