import os
import tomllib
from pathlib import Path
from typing import Dict, Any

class Config:
    """
    Manages loading, parsing, validation, and retrieval of settings from config.toml.
    Supports default values in case keys are missing.
    """
    
    DEFAULT_CONFIG = {
        "general": {
            "target_domain": "google.com",
            "max_domains": 500,
            "output_dir": "output",
            "timeout": 10,
            "concurrency": 15,
            "enable_screenshots": True,
        },
        "risk_thresholds": {
            "critical": 75,
            "high": 50,
            "medium": 25,
            "low": 0,
        },
        "risk_weights": {
            "whois_recent_registration": 15,
            "whois_no_organization": 5,
            "dns_has_mx": 15,
            "dns_suspicious_ns": 10,
            "ssl_missing_or_invalid": 15,
            "website_responds": 10,
            "website_has_login_fields": 20,
            "website_suspicious_keywords": 10,
            "brand_similarity_high": 20,
        }
    }
    
    def __init__(self, config_path: str = "config.toml"):
        self.config_path = Path(config_path)
        self.data: Dict[str, Any] = {}
        self.load()
        
    def load(self) -> None:
        """Loads configuration from config_path or uses defaults if file is not found."""
        if not self.config_path.exists():
            # If config file does not exist, use default config dict
            self.data = self.DEFAULT_CONFIG
            return
            
        try:
            with open(self.config_path, "rb") as f:
                self.data = tomllib.load(f)
        except Exception:
            # Fallback to default if there is a parsing error
            self.data = self.DEFAULT_CONFIG
            
        self._sanitize_and_validate()
        
    def _sanitize_and_validate(self) -> None:
        """Validates loaded keys and fills in default values if keys are missing."""
        for section, values in self.DEFAULT_CONFIG.items():
            if section not in self.data:
                self.data[section] = values
            else:
                for key, default_val in values.items():
                    if key not in self.data[section]:
                        self.data[section][key] = default_val
                        
        # Ensure output dir exists
        output_path = Path(self.data["general"]["output_dir"])
        output_path.mkdir(parents=True, exist_ok=True)
        
    @property
    def target_domain(self) -> str:
        return str(self.data["general"]["target_domain"]).lower().strip()
        
    @property
    def max_domains(self) -> int:
        return int(self.data["general"]["max_domains"])
        
    @property
    def output_dir(self) -> Path:
        return Path(self.data["general"]["output_dir"])
        
    @property
    def timeout(self) -> int:
        return int(self.data["general"]["timeout"])
        
    @property
    def concurrency(self) -> int:
        return int(self.data["general"]["concurrency"])
        
    @property
    def enable_screenshots(self) -> bool:
        return bool(self.data["general"]["enable_screenshots"])
        
    @property
    def risk_thresholds(self) -> Dict[str, int]:
        return {k: int(v) for k, v in self.data["risk_thresholds"].items()}
        
    @property
    def risk_weights(self) -> Dict[str, int]:
        return {k: int(v) for k, v in self.data["risk_weights"].items()}
