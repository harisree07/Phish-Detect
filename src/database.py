import sqlite3
import os
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger("phish_detect.database")

class DatabaseManager:
    """
    Manages SQLite storage for historical scans, domain checks, and changes tracking.
    """
    
    def __init__(self, output_dir: str = "output"):
        self.db_path = Path(output_dir) / "scans.db"
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize_db()
        
    def _initialize_db(self) -> None:
        """Creates tables if they do not exist."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Scan history table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS scans (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        target_domain TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        total_domains INTEGER NOT NULL,
                        registered_count INTEGER NOT NULL
                    )
                """)
                
                # Scanned domain detail results
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS domain_results (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id INTEGER NOT NULL,
                        domain TEXT NOT NULL,
                        registered INTEGER NOT NULL,
                        score INTEGER NOT NULL,
                        risk_level TEXT NOT NULL,
                        reasons TEXT NOT NULL,
                        registrar TEXT,
                        organization TEXT,
                        creation_date TEXT,
                        expiration_date TEXT,
                        a_records TEXT,
                        mx_records TEXT,
                        ns_records TEXT,
                        ssl_issuer TEXT,
                        ssl_valid_to TEXT,
                        screenshot_path TEXT,
                        FOREIGN KEY (scan_id) REFERENCES scans (id)
                    )
                """)
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to initialize SQLite database at {self.db_path}: {e}")
            
    def save_scan(self, target_domain: str, results: List[Dict[str, Any]]) -> int:
        """
        Saves a scan run and all checked domain details to the database.
        
        Returns:
            int: The inserted scan ID.
        """
        timestamp = datetime.utcnow().isoformat()
        total_domains = len(results)
        registered_count = sum(1 for r in results if r.get("whois", {}).get("registered", False) or r.get("dns", {}).get("resolves", False))
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Insert scan record
                cursor.execute(
                    "INSERT INTO scans (target_domain, timestamp, total_domains, registered_count) VALUES (?, ?, ?, ?)",
                    (target_domain, timestamp, total_domains, registered_count)
                )
                scan_id = cursor.lastrowid
                
                # Insert domains
                for item in results:
                    domain = item["domain"]
                    whois_d = item.get("whois", {})
                    dns_d = item.get("dns", {})
                    ssl_d = item.get("ssl", {})
                    
                    registered = 1 if (whois_d.get("registered") or dns_d.get("resolves")) else 0
                    score = item.get("score", 0)
                    risk_level = item.get("risk_level", "Low")
                    reasons = json.dumps(item.get("reasons", []))
                    
                    registrar = whois_d.get("registrar")
                    organization = whois_d.get("organization")
                    
                    c_date = whois_d.get("creation_date")
                    creation_date = c_date.isoformat() if isinstance(c_date, datetime) else str(c_date) if c_date else None
                    
                    e_date = whois_d.get("expiration_date")
                    expiration_date = e_date.isoformat() if isinstance(e_date, datetime) else str(e_date) if e_date else None
                    
                    a_records = json.dumps(dns_d.get("a_records", []))
                    mx_records = json.dumps(dns_d.get("mx_records", []))
                    ns_records = json.dumps(dns_d.get("ns_records", []))
                    
                    ssl_issuer = ssl_d.get("issuer")
                    s_to = ssl_d.get("valid_to")
                    ssl_valid_to = s_to.isoformat() if isinstance(s_to, datetime) else str(s_to) if s_to else None
                    
                    screenshot_path = item.get("screenshot_path")
                    
                    cursor.execute("""
                        INSERT INTO domain_results (
                            scan_id, domain, registered, score, risk_level, reasons,
                            registrar, organization, creation_date, expiration_date,
                            a_records, mx_records, ns_records, ssl_issuer, ssl_valid_to, screenshot_path
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        scan_id, domain, registered, score, risk_level, reasons,
                        registrar, organization, creation_date, expiration_date,
                        a_records, mx_records, ns_records, ssl_issuer, ssl_valid_to, screenshot_path
                    ))
                conn.commit()
                return scan_id
        except Exception as e:
            logger.error(f"Error inserting scan records to DB: {e}")
            return -1
            
    def get_last_scan_id(self, target_domain: str, exclude_id: Optional[int] = None) -> Optional[int]:
        """Gets the most recent scan ID for a target domain, optionally excluding a specific scan ID."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                if exclude_id is not None:
                    cursor.execute(
                        "SELECT id FROM scans WHERE target_domain = ? AND id != ? ORDER BY id DESC LIMIT 1",
                        (target_domain, exclude_id)
                    )
                else:
                    cursor.execute(
                        "SELECT id FROM scans WHERE target_domain = ? ORDER BY id DESC LIMIT 1",
                        (target_domain,)
                    )
                row = cursor.fetchone()
                return row[0] if row else None
        except Exception as e:
            logger.error(f"Error retrieving last scan ID: {e}")
            return None
            
    def get_scan_details(self, scan_id: int) -> List[Dict[str, Any]]:
        """Loads domain results for a specific scan ID."""
        results = []
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM domain_results WHERE scan_id = ?", (scan_id,))
                rows = cursor.fetchall()
                for row in rows:
                    results.append({
                        "domain": row["domain"],
                        "registered": bool(row["registered"]),
                        "score": row["score"],
                        "risk_level": row["risk_level"],
                        "reasons": json.loads(row["reasons"]),
                        "registrar": row["registrar"],
                        "organization": row["organization"],
                        "creation_date": row["creation_date"],
                        "expiration_date": row["expiration_date"],
                        "a_records": json.loads(row["a_records"]),
                        "mx_records": json.loads(row["mx_records"]),
                        "ns_records": json.loads(row["ns_records"]),
                        "ssl_issuer": row["ssl_issuer"],
                        "ssl_valid_to": row["ssl_valid_to"],
                        "screenshot_path": row["screenshot_path"]
                    })
        except Exception as e:
            logger.error(f"Error fetching scan details: {e}")
        return results
        
    def compare_scans(self, current_scan_id: int, previous_scan_id: int) -> Dict[str, Any]:
        """
        Compares results of two scans to identify new, removed, and updated registrations or risks.
        """
        comparison = {
            "new_registrations": [],
            "removed_registrations": [],
            "risk_increased": [],
            "risk_decreased": [],
            "dns_changed": []
        }
        
        current = {r["domain"]: r for r in self.get_scan_details(current_scan_id)}
        previous = {r["domain"]: r for r in self.get_scan_details(previous_scan_id)}
        
        for domain, curr_val in current.items():
            prev_val = previous.get(domain)
            
            if not prev_val:
                # Permutation didn't exist in previous run or wasn't tracked
                if curr_val["registered"]:
                    comparison["new_registrations"].append({
                        "domain": domain,
                        "current_score": curr_val["score"],
                        "current_risk": curr_val["risk_level"]
                    })
                continue
                
            # Track newly registered domains
            if curr_val["registered"] and not prev_val["registered"]:
                comparison["new_registrations"].append({
                    "domain": domain,
                    "current_score": curr_val["score"],
                    "current_risk": curr_val["risk_level"]
                })
                
            # Track removed registrations
            elif not curr_val["registered"] and prev_val["registered"]:
                comparison["removed_registrations"].append(domain)
                
            # Check score changes
            elif curr_val["registered"] and prev_val["registered"]:
                if curr_val["score"] > prev_val["score"]:
                    comparison["risk_increased"].append({
                        "domain": domain,
                        "old_score": prev_val["score"],
                        "new_score": curr_val["score"],
                        "old_risk": prev_val["risk_level"],
                        "new_risk": curr_val["risk_level"]
                    })
                elif curr_val["score"] < prev_val["score"]:
                    comparison["risk_decreased"].append({
                        "domain": domain,
                        "old_score": prev_val["score"],
                        "new_score": curr_val["score"],
                        "old_risk": prev_val["risk_level"],
                        "new_risk": curr_val["risk_level"]
                    })
                    
                # Check A records (IP) changes
                if set(curr_val["a_records"]) != set(prev_val["a_records"]):
                    comparison["dns_changed"].append({
                        "domain": domain,
                        "old_ips": prev_val["a_records"],
                        "new_ips": curr_val["a_records"]
                    })
                    
        # Check domains that were in previous but deleted from current config completely
        for domain, prev_val in previous.items():
            if domain not in current and prev_val["registered"]:
                comparison["removed_registrations"].append(domain)
                
        return comparison
