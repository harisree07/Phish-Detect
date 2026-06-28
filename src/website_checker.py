import requests
from bs4 import BeautifulSoup
from typing import Dict, Any, List
import logging

logger = logging.getLogger("phish_detect.website")

class WebsiteChecker:
    """
    Sends HTTP/HTTPS requests to check website reachability, response codes,
    redirection behavior, and parses homepage content for phishing indicators.
    """
    
    # Common phishing indicators to look for in the HTML body/title/inputs
    PHISHING_INDICATORS = [
        "login", "verify", "sign in", "secure login", "update payment",
        "verify account", "bank", "password", "security question", "credential",
        "confirm identity", "billing update", "customer support"
    ]
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        
    def check_website(self, domain: str) -> Dict[str, Any]:
        """
        Queries HTTP/HTTPS for the domain, follows redirects, and inspects elements.
        
        Args:
            domain (str): Domain to inspect.
            
        Returns:
            Dict[str, Any]: Web content details:
                - reachable (bool)
                - status_code (int or None)
                - final_url (str or None)
                - redirect_history (list of str)
                - title (str or None)
                - meta_description (str or None)
                - forms (list of dict)
                - has_password_field (bool)
                - detected_keywords (list of str)
                - raw_html (str or None)
        """
        result = {
            "reachable": False,
            "status_code": None,
            "final_url": None,
            "redirect_history": [],
            "title": None,
            "meta_description": None,
            "forms": [],
            "has_password_field": False,
            "detected_keywords": [],
            "raw_html": None
        }
        
        # Test HTTPS first, fallback to HTTP if fails
        urls_to_test = [f"https://{domain}", f"http://{domain}"]
        response = None
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
        
        for url in urls_to_test:
            try:
                logger.debug(f"Requesting URL: {url}")
                response = requests.get(url, timeout=self.timeout, headers=headers, allow_redirects=True)
                # Successful connection, break early
                break
            except requests.RequestException as e:
                logger.debug(f"Request failed for {url}: {e}")
                
        if response is None:
            return result
            
        result["reachable"] = True
        result["status_code"] = response.status_code
        result["final_url"] = response.url
        
        # Record redirect history
        if response.history:
            result["redirect_history"] = [resp.url for resp in response.history]
            
        try:
            content = response.text
            result["raw_html"] = content
            soup = BeautifulSoup(content, "html.parser")
            
            # Extract HTML title
            if soup.title and soup.title.string:
                result["title"] = str(soup.title.string).strip()
                
            # Extract meta description
            meta_desc = soup.find("meta", attrs={"name": "description"})
            if meta_desc and meta_desc.get("content"):
                result["meta_description"] = str(meta_desc.get("content")).strip()
                
            # Parse form details
            forms = soup.find_all("form")
            for f in forms:
                form_data = {
                    "action": f.get("action"),
                    "method": f.get("method", "get").lower(),
                    "inputs": []
                }
                inputs = f.find_all("input")
                for inp in inputs:
                    inp_type = inp.get("type", "text").lower()
                    inp_name = inp.get("name")
                    form_data["inputs"].append({"type": inp_type, "name": inp_name})
                    if inp_type == "password":
                        result["has_password_field"] = True
                        
                result["forms"].append(form_data)
                
            # Even if password fields are not in a form tag, look for them directly
            if not result["has_password_field"]:
                pwd_inputs = soup.find_all("input", type="password")
                if pwd_inputs:
                    result["has_password_field"] = True
                    
            # Extract keywords in body
            body_text = ""
            if soup.body:
                body_text = soup.body.get_text().lower()
            else:
                body_text = content.lower()
                
            title_text = (result["title"] or "").lower()
            
            for keyword in self.PHISHING_INDICATORS:
                if keyword in body_text or keyword in title_text:
                    result["detected_keywords"].append(keyword)
                    
        except Exception as e:
            logger.error(f"Error parsing HTML content from {domain}: {e}")
            
        return result
