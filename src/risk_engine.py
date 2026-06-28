from datetime import datetime, timedelta
from typing import Dict, Any, List, Tuple
import logging

logger = logging.getLogger("phish_detect.risk_engine")

class RiskEngine:
    """
    Computes a risk score (0 to 100) and maps it to a risk level (Low, Medium, High, Critical)
    using weighted factors based on domain registration age, DNS records, SSL state,
    and webpage content similarity.
    """
    
    def __init__(self, thresholds: Dict[str, int], weights: Dict[str, int]):
        self.thresholds = thresholds
        self.weights = weights
        # Compute maximum possible points to normalize final score to a 0-100 range
        self.max_possible_points = sum(self.weights.values())
        
    def calculate_risk(self, analysis_data: Dict[str, Any]) -> Tuple[int, str, List[str]]:
        """
        Calculates the risk score, risk level, and identifies matching risk reasons.
        
        Args:
            analysis_data (Dict[str, Any]): Dictionary of checker results containing keys:
                - whois: results from WhoisChecker
                - dns: results from DnsChecker
                - ssl: results from SslChecker
                - website: results from WebsiteChecker
                - brand: results from BrandDetector
                
        Returns:
            Tuple[int, str, List[str]]: (Score (0-100), Risk Level string, List of reasons)
        """
        score_points = 0
        reasons = []
        
        whois_data = analysis_data.get("whois", {})
        dns_data = analysis_data.get("dns", {})
        ssl_data = analysis_data.get("ssl", {})
        web_data = analysis_data.get("website", {})
        brand_data = analysis_data.get("brand", {})
        
        # 1. WHOIS recent registration check (e.g., registered in past 90 days)
        if whois_data.get("registered") and whois_data.get("creation_date"):
            creation_date = whois_data["creation_date"]
            if isinstance(creation_date, datetime):
                # Ensure offset-naive UTC comparison
                if creation_date.tzinfo is not None:
                    creation_date = creation_date.replace(tzinfo=None)
                age_days = (datetime.utcnow() - creation_date).days
                if age_days < 90:
                    weight = self.weights.get("whois_recent_registration", 0)
                    score_points += weight
                    reasons.append(f"Domain registered recently ({age_days} days ago) [+{weight} pts]")
                    
        # 2. WHOIS organization is redacted/empty
        if whois_data.get("registered") and not whois_data.get("organization"):
            weight = self.weights.get("whois_no_organization", 0)
            score_points += weight
            reasons.append(f"Registrant organization is hidden or empty in WHOIS [+{weight} pts]")
            
        # 3. DNS MX configured check (Active MX means capability to send emails imitating brand)
        if dns_data.get("mx_records"):
            weight = self.weights.get("dns_has_mx", 0)
            score_points += weight
            reasons.append(f"Active mail exchange (MX) record configured [+{weight} pts]")
            
        # 4. DNS Name servers check
        ns_records = dns_data.get("ns_records", [])
        # Check for single name server or nameservers referencing generic/free/suspicious ones
        is_suspicious_ns = False
        for ns in ns_records:
            # Simple heuristic: less than standard registrar NS, or dynamic DNS services
            if any(term in ns.lower() for term in ["duckdns", "no-ip", "dyndns", "freedns"]):
                is_suspicious_ns = True
                break
        if is_suspicious_ns or (ns_records and len(ns_records) == 1):
            weight = self.weights.get("dns_suspicious_ns", 0)
            score_points += weight
            reasons.append(f"Suspicious or single Name Server configuration [+{weight} pts]")
            
        # 5. Website online check
        if web_data.get("reachable"):
            weight = self.weights.get("website_responds", 0)
            score_points += weight
            reasons.append(f"Website is active and reachable (HTTP {web_data.get('status_code')}) [+{weight} pts]")
            
        # 6. SSL missing or invalid
        # If site is active and has either no SSL, or expired SSL, or self-signed
        if web_data.get("reachable"):
            ssl_failed = not ssl_data.get("has_ssl") or ssl_data.get("is_expired") or ssl_data.get("is_self_signed")
            if ssl_failed:
                weight = self.weights.get("ssl_missing_or_invalid", 0)
                score_points += weight
                details = []
                if not ssl_data.get("has_ssl"):
                    details.append("SSL missing")
                if ssl_data.get("is_expired"):
                    details.append("SSL expired")
                if ssl_data.get("is_self_signed"):
                    details.append("Self-signed certificate")
                reasons.append(f"Invalid/Missing SSL configuration ({', '.join(details)}) [+{weight} pts]")
                
        # 7. Login forms/password fields check
        if web_data.get("has_password_field"):
            weight = self.weights.get("website_has_login_fields", 0)
            score_points += weight
            reasons.append(f"Webpage contains credential input fields or password entry [+{weight} pts]")
            
        # 8. Webpage phishing keywords check
        keywords = web_data.get("detected_keywords", [])
        if keywords:
            weight = self.weights.get("website_suspicious_keywords", 0)
            score_points += weight
            reasons.append(f"Phishing indicators detected in webpage text: {', '.join(keywords)} [+{weight} pts]")
            
        # 9. Brand similarity high check
        if brand_data.get("brand_name_matches") or brand_data.get("logo_hotlinking") or brand_data.get("text_similarity", 0.0) > 0.4:
            weight = self.weights.get("brand_similarity_high", 0)
            score_points += weight
            details = []
            if brand_data.get("brand_name_matches"):
                details.append("brand name used")
            if brand_data.get("logo_hotlinking"):
                details.append("logo hotlinked")
            if brand_data.get("text_similarity", 0.0) > 0.4:
                details.append(f"text similarity is {brand_data['text_similarity']:.0%}")
            reasons.append(f"Brand impersonation indicators matching reference ({', '.join(details)}) [+{weight} pts]")
            
        # Normalize score to 0-100 range
        if self.max_possible_points > 0:
            final_score = int((score_points / self.max_possible_points) * 100)
        else:
            final_score = 0
            
        # Bind max score to 100
        final_score = min(final_score, 100)
        
        # Categorize risk level
        risk_level = "Low"
        if final_score >= self.thresholds.get("critical", 75):
            risk_level = "Critical"
        elif final_score >= self.thresholds.get("high", 50):
            risk_level = "High"
        elif final_score >= self.thresholds.get("medium", 25):
            risk_level = "Medium"
            
        return final_score, risk_level, reasons
