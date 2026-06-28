import argparse
import sys
import os
import concurrent.futures
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List

# Core internal module imports
from config import Config
from logger import setup_logger
from generator import DomainGenerator
from whois_checker import WhoisChecker
from dns_checker import DnsChecker
from ssl_checker import SslChecker
from website_checker import WebsiteChecker
from brand_detector import BrandDetector
from screenshot_manager import ScreenshotManager
from risk_engine import RiskEngine
from database import DatabaseManager
from report_generator import ReportGenerator

def parse_args() -> argparse.Namespace:
    """Parses command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Spot Phishing Domains Automatically - Automated Brand Typosquatting Threat Intelligence Tool."
    )
    parser.add_argument(
        "--domain",
        type=str,
        help="Target legitimate brand domain to monitor (e.g. google.com). Overrides config.toml."
    )
    parser.add_argument(
        "--config",
        type=str,
        default="config.toml",
        help="Path to the TOML configuration file (default: config.toml)."
    )
    parser.add_argument(
        "--no-screenshots",
        action="store_true",
        help="Disables headless browser screenshot capture even if enabled in config."
    )
    parser.add_argument(
        "-i", "--interactive",
        action="store_true",
        help="Starts clean, interactive command-line terminal to query single domains dynamically."
    )
    return parser.parse_args()


def run_interactive_terminal(
    target_domain: str,
    whois_checker: WhoisChecker,
    dns_checker: DnsChecker,
    ssl_checker: SslChecker,
    website_checker: WebsiteChecker,
    brand_detector: BrandDetector,
    risk_engine: RiskEngine
):
    """Starts a clean, interactive user terminal loop to query single domains."""
    # Enable ANSI escape characters in Windows Console if needed
    os.system("")
    
    print("\n" + "=" * 60)
    print(" \033[96m🔍 PHISH-DETECT INTERACTIVE THREAT TERMINAL 🔍\033[0m")
    print("=" * 60)
    print(f"Target Brand Base : \033[95m{target_domain}\033[0m")
    print("Type any domain name (e.g., googly-login.com) to calculate its risk.")
    print("Type \033[93m'exit'\033[0m to quit.\n")
    
    while True:
        try:
            domain = input("\033[1;32mDomain > \033[0m").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting interactive shell.")
            break
            
        if not domain:
            continue
        if domain in ["exit", "quit"]:
            print("Exiting interactive shell. Goodbye!")
            break
            
        print(f"Analyzing \033[94m'{domain}'\033[0m... Please wait...")
        
        # Sequentially run checks on the query domain
        dns_res = dns_checker.resolve_all(domain)
        whois_res = whois_checker.check_domain(domain)
        
        is_active = dns_res.get("resolves", False)
        is_registered = whois_res.get("registered", False)
        
        ssl_res = {
            "has_ssl": False, "issuer": None, "subject": None,
            "valid_from": None, "valid_to": None, "is_expired": False,
            "is_self_signed": False, "is_wildcard": False, "error": None
        }
        web_res = {
            "reachable": False, "status_code": None, "final_url": None,
            "redirect_history": [], "title": None, "meta_description": None,
            "forms": [], "has_password_field": False, "detected_keywords": [], "raw_html": None
        }
        brand_res = {
            "brand_name_matches": False, "logo_hotlinking": False,
            "text_similarity": 0.0, "similar_title": False, "indicators": []
        }
        
        if is_active or is_registered:
            ssl_res = ssl_checker.check_certificate(domain)
            web_res = website_checker.check_website(domain)
            if web_res.get("reachable") and web_res.get("raw_html"):
                brand_res = brand_detector.analyze_impersonation(web_res["raw_html"], domain)
                
        analysis = {
            "whois": whois_res,
            "dns": dns_res,
            "ssl": ssl_res,
            "website": web_res,
            "brand": brand_res
        }
        
        score, risk_level, reasons = risk_engine.calculate_risk(analysis)
        
        # Color coding
        color = "\033[92m" # Green
        if risk_level == "Critical":
            color = "\033[91m" # Red
        elif risk_level == "High":
            color = "\033[93m" # Orange/Yellow
        elif risk_level == "Medium":
            color = "\033[94m" # Blue
        reset = "\033[0m"
        
        print("\n" + "-" * 50)
        print(f"RESULTS FOR: \033[1m{domain.upper()}\033[0m")
        print("-" * 50)
        print(f"Risk Rating : {color}{risk_level} ({score}%){reset}")
        print(f"Status      : {'\033[92mONLINE\033[0m' if is_active else '\033[90mOFFLINE\033[0m'} | {'\033[93mREGISTERED\033[0m' if is_registered else '\033[90mUNREGISTERED\033[0m'}")
        
        if whois_res.get("registered"):
            print(f"Registrar   : {whois_res.get('registrar', 'Unknown')}")
            if whois_res.get("creation_date"):
                c_date = whois_res.get("creation_date")
                c_str = c_date.strftime("%Y-%m-%d") if isinstance(c_date, datetime) else str(c_date)[:10]
                print(f"Created On  : {c_str}")
                
        if dns_res.get("a_records"):
            print(f"IP Address  : {', '.join(dns_res['a_records'])}")
        if dns_res.get("mx_records"):
            print(f"Mail Servers: {', '.join(dns_res['mx_records'])}")
            
        print("\n\033[1mRisk Indicators Checked:\033[0m")
        if reasons:
            for reason in reasons:
                print(f"  - {reason}")
        else:
            print("  - No risks identified.")
        print("-" * 50 + "\n")


def scan_worker(
    domain: str,
    whois_checker: WhoisChecker,
    dns_checker: DnsChecker,
    ssl_checker: SslChecker,
    website_checker: WebsiteChecker,
    brand_detector: BrandDetector,
    screenshot_manager: ScreenshotManager,
    risk_engine: RiskEngine,
    enable_screenshots: bool,
    logger
) -> Dict[str, Any]:
    """
    Executes checks sequentially for a single domain permutation.
    This runs inside a ThreadPoolExecutor worker.
    """
    logger.info(f"Scanning domain: {domain}")
    
    # 1. DNS check first as a fast filter
    dns_result = dns_checker.resolve_all(domain)
    
    # 2. WHOIS lookup
    whois_result = whois_checker.check_domain(domain)
    
    # Check if domain appears active or registered
    is_active = dns_result.get("resolves", False)
    is_registered = whois_result.get("registered", False)
    
    # Initialize dependent results as default empty objects
    ssl_result = {
        "has_ssl": False, "issuer": None, "subject": None,
        "valid_from": None, "valid_to": None, "is_expired": False,
        "is_self_signed": False, "is_wildcard": False, "error": None
    }
    web_result = {
        "reachable": False, "status_code": None, "final_url": None,
        "redirect_history": [], "title": None, "meta_description": None,
        "forms": [], "has_password_field": False, "detected_keywords": [], "raw_html": None
    }
    brand_result = {
        "brand_name_matches": False, "logo_hotlinking": False,
        "text_similarity": 0.0, "similar_title": False, "indicators": []
    }
    screenshot_path = None
    
    # If the domain resolves or has WHOIS, inspect website details
    if is_active or is_registered:
        # 3. SSL Check
        ssl_result = ssl_checker.check_certificate(domain)
        
        # 4. Webpage checker
        web_result = website_checker.check_website(domain)
        
        # 5. Brand similarity comparison
        if web_result.get("reachable") and web_result.get("raw_html"):
            brand_result = brand_detector.analyze_impersonation(
                web_result["raw_html"],
                domain
            )
            
        # 6. Screenshot Capture (if online and screenshots enabled)
        if enable_screenshots and web_result.get("reachable"):
            logger.info(f"Capturing screenshot for: {domain}")
            screenshot_path = screenshot_manager.capture(domain)
            
    # Combine results
    analysis_data = {
        "whois": whois_result,
        "dns": dns_result,
        "ssl": ssl_result,
        "website": web_result,
        "brand": brand_result
    }
    
    # 7. Calculate Risk Score
    score, risk_level, reasons = risk_engine.calculate_risk(analysis_data)
    
    # Packaged result
    return {
        "domain": domain,
        "registered": is_registered or is_active,
        "score": score,
        "risk_level": risk_level,
        "reasons": reasons,
        "whois": whois_result,
        "dns": dns_result,
        "ssl": ssl_result,
        "website": {k: v for k, v in web_result.items() if k != "raw_html"}, # Exclude raw HTML from final json reports
        "brand": brand_result,
        "screenshot_path": screenshot_path
    }

def main() -> None:
    args = parse_args()
    
    # Load settings
    config = Config(args.config)
    
    # Output path setup
    output_dir = config.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Setup logger
    logger = setup_logger(str(output_dir))
    logger.info("Initializing Spot Phishing Domains Automatically...")
    
    target_domain = args.domain or config.target_domain
    logger.info(f"Target Legitimate Domain: {target_domain}")
    
    # Setup checker components
    whois_checker = WhoisChecker(timeout=config.timeout)
    dns_checker = DnsChecker(timeout=config.timeout)
    ssl_checker = SslChecker(timeout=config.timeout)
    website_checker = WebsiteChecker(timeout=config.timeout)
    brand_detector = BrandDetector(target_domain)
    screenshot_manager = ScreenshotManager(output_dir=str(output_dir), timeout=config.timeout)
    risk_engine = RiskEngine(thresholds=config.risk_thresholds, weights=config.risk_weights)
    db_manager = DatabaseManager(output_dir=str(output_dir))
    report_generator = ReportGenerator(output_dir=str(output_dir))
    
    # Fetch content of legitimate domain to use as similarity baseline
    logger.info(f"Fetching legitimate domain reference page: {target_domain}")
    ref_web_data = website_checker.check_website(target_domain)
    if ref_web_data.get("reachable") and ref_web_data.get("raw_html"):
        brand_detector.set_reference_content(ref_web_data["raw_html"])
        logger.info("Legitimate domain reference page parsed successfully.")
    else:
        logger.warning(
            f"Could not reach target legitimate domain ({target_domain}). "
            "Continuing with empty similarity base text."
        )
        
    # Trigger interactive shell if requested by the user
    if args.interactive:
        run_interactive_terminal(
            target_domain,
            whois_checker,
            dns_checker,
            ssl_checker,
            website_checker,
            brand_detector,
            risk_engine
        )
        return
        
        
    # Generate variations
    logger.info("Generating typosquatting permutations...")
    generator = DomainGenerator(target_domain)
    domain_permutations = generator.generate(max_domains=config.max_domains)
    logger.info(f"Generated {len(domain_permutations)} unique domain variations to scan.")
    
    if not domain_permutations:
        logger.warning("No domain variations were generated. Terminating.")
        sys.exit(0)
        
    # Run scans concurrently using thread pool
    results: List[Dict[str, Any]] = []
    concurrency_limit = config.concurrency
    enable_screenshots = config.enable_screenshots and not args.no_screenshots
    
    start_time = datetime.utcnow()
    logger.info(f"Starting domain scan pool with {concurrency_limit} concurrent workers...")
    
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency_limit) as executor:
            future_to_domain = {
                executor.submit(
                    scan_worker,
                    domain,
                    whois_checker,
                    dns_checker,
                    ssl_checker,
                    website_checker,
                    brand_detector,
                    screenshot_manager,
                    risk_engine,
                    enable_screenshots,
                    logger
                ): domain for domain in domain_permutations
            }
            
            for future in concurrent.futures.as_completed(future_to_domain):
                domain = future_to_domain[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    logger.error(f"Scan execution failed for {domain}: {e}")
    except KeyboardInterrupt:
        logger.warning("Execution interrupted by user. Saving partial results.")
        
    duration = (datetime.utcnow() - start_time).total_seconds()
    logger.info(f"Scan loop finished. Duration: {duration:.2f}s")
    
    # Save scan results to SQLite database
    logger.info("Saving scan history to SQLite database...")
    scan_id = db_manager.save_scan(target_domain, results)
    
    # Perform scan diff comparison against previous scan
    comparison = None
    prev_scan_id = db_manager.get_last_scan_id(target_domain, exclude_id=scan_id)
    if prev_scan_id:
        logger.info(f"Comparing current scan (ID: {scan_id}) with previous scan (ID: {prev_scan_id})...")
        comparison = db_manager.compare_scans(scan_id, prev_scan_id)
        
    # Generate reports
    logger.info("Generating report documents...")
    report_paths = report_generator.generate_all(target_domain, results, comparison)
    
    logger.info("Assessment completed successfully.")
    for fmt, path in report_paths.items():
        logger.info(f"  {fmt.upper()} Report: {path}")

if __name__ == "__main__":
    main()
