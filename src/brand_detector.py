import logging
from bs4 import BeautifulSoup
import difflib
from typing import Dict, Any, List

logger = logging.getLogger("phish_detect.brand")

class BrandDetector:
    """
    Compares webpage contents of a suspected typosquatted domain against a reference
    target brand domain to identify brand impersonation and logo hotlinking.
    """
    
    def __init__(self, target_domain: str):
        self.target_domain = target_domain.lower().strip()
        # Extract base brand name (e.g. google.com -> google)
        self.brand_name = self.target_domain.split('.')[0]
        self.reference_text = ""
        self.reference_title = ""
        
    def set_reference_content(self, raw_html: str) -> None:
        """Loads and pre-processes the reference homepage content of the legitimate brand."""
        if not raw_html:
            return
        try:
            soup = BeautifulSoup(raw_html, "html.parser")
            if soup.title:
                self.reference_title = str(soup.title.string or "").strip()
            
            # Extract plain text content
            if soup.body:
                self.reference_text = soup.body.get_text()
            else:
                self.reference_text = soup.get_text()
                
            # Clean up white spaces
            self.reference_text = " ".join(self.reference_text.split())
        except Exception as e:
            logger.error(f"Error parsing reference page content: {e}")
            
    def analyze_impersonation(self, suspected_html: str, suspected_domain: str) -> Dict[str, Any]:
        """
        Analyzes a suspicious webpage for brand indicators and calculates a similarity rating.
        
        Args:
            suspected_html (str): Raw HTML of the suspected phishing site.
            suspected_domain (str): Domain of the suspected site.
            
        Returns:
            Dict[str, Any]: Analytics details:
                - brand_name_matches (bool)
                - logo_hotlinking (bool)
                - text_similarity (float, 0.0 - 1.0)
                - similar_title (bool)
                - indicators (list of str)
        """
        result = {
            "brand_name_matches": False,
            "logo_hotlinking": False,
            "text_similarity": 0.0,
            "similar_title": False,
            "indicators": []
        }
        
        if not suspected_html:
            return result
            
        try:
            soup = BeautifulSoup(suspected_html, "html.parser")
            
            # 1. Brand name in text or title
            title = ""
            if soup.title and soup.title.string:
                title = str(soup.title.string).strip()
                
            body_text = ""
            if soup.body:
                body_text = soup.body.get_text()
            else:
                body_text = soup.get_text()
            body_text = " ".join(body_text.split())
            
            # Check for occurrences of the brand name in target page
            # Case insensitive check
            if self.brand_name in body_text.lower() or self.brand_name in title.lower():
                result["brand_name_matches"] = True
                result["indicators"].append(f"Brand name '{self.brand_name}' referenced on webpage/title")
                
            # 2. Check title similarity
            if title and self.reference_title:
                title_ratio = difflib.SequenceMatcher(None, title.lower(), self.reference_title.lower()).ratio()
                if title_ratio > 0.6:
                    result["similar_title"] = True
                    result["indicators"].append(f"Webpage title is highly similar (similarity: {title_ratio:.1%})")
                    
            # 3. Logo Hotlinking or Referencing
            # Look for images hotlinking assets directly from the legitimate target domain
            images = soup.find_all("img")
            for img in images:
                src = img.get("src", "")
                if not src:
                    continue
                # If logo source includes the legitimate domain (e.g. google.com/logo.png)
                if self.target_domain in src.lower():
                    result["logo_hotlinking"] = True
                    result["indicators"].append(f"Hotlinking or referencing assets from target domain: {src}")
                    break
                # Or check if filename contains brand logo terms
                if self.brand_name in src.lower() and "logo" in src.lower():
                    result["indicators"].append(f"Matches brand logo image filename: {src}")
                    
            # 4. Text Content Similarity
            if body_text and self.reference_text:
                # We limit comparison length to keep it snappy
                suspect_sample = body_text[:5000].lower()
                ref_sample = self.reference_text[:5000].lower()
                
                # Check similarity ratio
                ratio = difflib.SequenceMatcher(None, suspect_sample, ref_sample).ratio()
                result["text_similarity"] = ratio
                if ratio > 0.4:
                    result["indicators"].append(f"Text content similarity is high (similarity: {ratio:.1%})")
                    
        except Exception as e:
            logger.error(f"Error executing brand impersonation analysis for {suspected_domain}: {e}")
            
        return result
