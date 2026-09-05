#!/usr/bin/env python3
"""
subdomain-enum - Fast subdomain enumeration and takeover detector
"""

import argparse
import concurrent.futures
import itertools
import json
import os
import socket
import sys
import time
from typing import List, Dict, Optional, Set

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("[!] requests library not found. Install with: pip install requests", file=sys.stderr)

# Default wordlist (small subset for demo, real tool would use a large file)
DEFAULT_WORDLIST = """
www
mail
ftp
admin
api
dev
test
staging
blog
shop
portal
secure
vpn
remote
webmail
support
docs
help
news
forum
static
assets
cdn
img
images
video
download
downloads
archive
old
new
beta
alpha
demo
lab
internal
intranet
extranet
"""

class SubdomainEnumerator:
    def __init__(self, domain: str, wordlist: List[str], timeout: float = 3.0, 
                 max_workers: int = 20, verbose: bool = False):
        self.domain = domain.lower().strip()
        self.wordlist = wordlist
        self.timeout = timeout
        self.max_workers = max_workers
        self.verbose = verbose
        self.found_subdomains: Set[str] = set()
        self.takeover_candidates: List[Dict] = []
        self.session = requests.Session() if REQUESTS_AVAILABLE else None
        
    def log(self, message: str, level: str = "info"):
        """Simple logging function"""
        if self.verbose or level == "error":
            prefix = {
                "info": "[*]",
                "success": "[+]",
                "error": "[!]",
                "warning": "[-]"
            }.get(level, "[*]")
            print(f"{prefix} {message}")
    
    def check_subdomain(self, subdomain: str) -> Optional[str]:
        """Try to resolve a subdomain to an IP address"""
        full_domain = f"{subdomain}.{self.domain}"
        try:
            ip = socket.gethostbyname(full_domain)
            self.log(f"Found: {full_domain} -> {ip}", "success")
            return full_domain
        except socket.gaierror:
            return None
        except Exception as e:
            self.log(f"Error checking {full_domain}: {str(e)}", "error")
            return None
    
    def check_takeover(self, subdomain: str) -> Optional[Dict]:
        """Check if a subdomain is vulnerable to takeover"""
        if not REQUESTS_AVAILABLE:
            return None
        
        url = f"http://{subdomain}"
        takeover_indicators = [
            "No such app",
            "There isn't a GitHub Pages site here",
            "This site can't be reached",
            "The specified bucket does not exist",
            "NoSuchBucket",
            "No such account",
            "There is no app configured",
            "Something has gone wrong",
            "Not Found",
            "This page is not available",
            "Domain doesn't exist",
            "The service is not available"
        ]
        
        try:
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            content = response.text.lower()
            
            for indicator in takeover_indicators:
                if indicator.lower() in content:
                    self.log(f"Potential takeover: {subdomain} - {indicator}", "warning")
                    return {
                        "subdomain": subdomain,
                        "indicator": indicator,
                        "status_code": response.status_code,
                        "url": url
                    }
        except requests.exceptions.ConnectionError:
            pass
        except requests.exceptions.Timeout:
            pass
        except Exception as e:
            self.log(f"Error checking takeover for {subdomain}: {str(e)}", "error")
        
        return None
    
    def enumerate(self) -> None:
        """Main enumeration function"""
        self.log(f"Starting enumeration for {self.domain}")
        self.log(f"Wordlist size: {len(self.wordlist)}")
        
        start_time = time.time()
        
        # Generate all subdomains to check
        subdomains = [f"{word}.{self.domain}" for word in self.wordlist]
        
        # Multi-threaded DNS resolution
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_subdomain = {
                executor.submit(self.check_subdomain, word): word 
                for word in self.wordlist
            }
            
            for future in concurrent.futures.as_completed(future_to_subdomain):
                result = future.result()
                if result:
                    self.found_subdomains.add(result)
        
        # Check takeover candidates
        self.log(f"Checking takeover candidates for {len(self.found_subdomains)} subdomains")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_subdomain = {
                executor.submit(self.check_takeover, subdomain): subdomain
                for subdomain in self.found_subdomains
            }
            
            for future in concurrent.futures.as_completed(future_to_subdomain):
                result = future.result()
                if result:
                    self.takeover_candidates.append(result)
        
        elapsed_time = time.time() - start_time
        self.log(f"Enumeration completed in {elapsed_time:.2f} seconds")
    
    def get_results(self) -> Dict:
        """Return results in structured format"""
        return {
            "domain": self.domain,
            "subdomains": sorted(list(self.found_subdomains)),
            "takeover_candidates": self.takeover_candidates
        }
    
    def save_results(self, output_file: Optional[str] = None) -> None:
        """Save results to file"""
        results = self.get_results()
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            self.log(f"Results saved to {output_file}", "success")
        else:
            # Print results to console
            print("\n" + "=" * 60)
            print("ENUMERATION RESULTS")
            print("=" * 60)
            print(f"Domain: {self.domain}")
            print(f"Subdomains found: {len(results['subdomains'])}")
            
            if results['subdomains']:
                print("\nSubdomains:")
                for subdomain in results['subdomains']:
                    print(f"  {subdomain}")
            
            if results['takeover_candidates']:
                print("\nTakeover candidates:")
                for candidate in results['takeover_candidates']:
                    print(f"  {candidate['subdomain']} - {candidate['indicator']}")
                    print(f"    URL: {candidate['url']}")
            else:
                print("\nNo takeover candidates found")

def load_wordlist(wordlist_file: Optional[str] = None) -> List[str]:
    """Load wordlist from file or use default"""
    if wordlist_file:
        try:
            with open(wordlist_file, 'r') as f:
                words = [line.strip() for line in f if line.strip()]
                return words
        except FileNotFoundError:
            print(f"[!] Wordlist file not found: {wordlist_file}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"[!] Error reading wordlist: {str(e)}", file=sys.stderr)
            sys.exit(1)
    else:
        return [w for w in DEFAULT_WORDLIST.split('\n') if w.strip()]

def main():
    parser = argparse.ArgumentParser(
        description="Subdomain enumeration and takeover detection tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python subdomain-enum.py example.com
  python subdomain-enum.py example.com -w wordlist.txt -o results.json
  python subdomain-enum.py example.com -t 5 -w 50 -v
        """
    )
    
    parser.add_argument("domain", help="Target domain to enumerate")
    parser.add_argument("-w", "--wordlist", help="Custom wordlist file")
    parser.add_argument("-o", "--output", help="Output file for results (JSON)")
    parser.add_argument("-t", "--timeout", type=float, default=3.0, 
                       help="HTTP timeout in seconds (default: 3)")
    parser.add_argument("-m", "--max-workers", type=int, default=20,
                       help="Maximum concurrent workers (default: 20)")
    parser.add_argument("-v", "--verbose", action="store_true",
                       help="Enable verbose output")
    
    args = parser.parse_args()
    
    # Validate domain
    if not args.domain or '.' not in args.domain:
        print("[!] Invalid domain format", file=sys.stderr)
        sys.exit(1)
    
    # Load wordlist
    wordlist = load_wordlist(args.wordlist)
    
    # Create enumerator and run
    enumerator = SubdomainEnumerator(
        domain=args.domain,
        wordlist=wordlist,
        timeout=args.timeout,
        max_workers=args.max_workers,
        verbose=args.verbose
    )
    
    try:
        enumerator.enumerate()
        enumerator.save_results(args.output)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"[!] Fatal error: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()