# Required packages
import requests
from bs4 import BeautifulSoup
import urllib.parse
import colorama
import re
from concurrent.futures import ThreadPoolExecutor
import sys
from typing import List, Dict, Set



class WebSecurityScanner:
    def __init__(self, target_url: str, max_depth: int = 3):
        """
        Initialize the security scanner with a target URL and maximum crawl depth.

        Args:
            target_url: The base URL to scan
            max_depth: Maximum depth for crawling links (default: 3)
        """
        self.target_url = target_url
        self.max_depth = max_depth
        self.visited_urls: Set[str] = set()
        self.vulnerabilities: List[Dict] = []
        self.session = requests.Session()

        # Initialize colorama for cross-platform colored output
        colorama.init()

    def normalize_url(self, url: str) -> str:
        """Normalize the URL to prevent duplicate checks"""
        parsed = urllib.parse.urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    

    def crawl(self, url: str, depth: int = 0) -> None:
    """
    Crawl the website to discover pages and endpoints.

    Args:
        url: Current URL to crawl
        depth: Current depth in the crawl tree
    """
    if depth > self.max_depth or url in self.visited_urls:
        return

    try:
        self.visited_urls.add(url)
        response = self.session.get(url, verify=False)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Find all links in the page
        links = soup.find_all('a', href=True)
        for link in links:
            next_url = urllib.parse.urljoin(url, link['href'])
            if next_url.startswith(self.target_url):
                self.crawl(next_url, depth + 1)

    except Exception as e:
        print(f"Error crawling {url}: {str(e)}")


def check_sql_injection(self, url: str) -> None:
    """Test for potential SQL injection vulnerabilities"""
    sql_payloads = ["'", "1' OR '1'='1", "' OR 1=1--", "' UNION SELECT NULL--"]

    for payload in sql_payloads:
        try:
            # Test GET parameters
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)

            for param in params:
                test_url = url.replace(f"{param}={params[param][0]}", 
                                     f"{param}={payload}")
                response = self.session.get(test_url)

                # Look for SQL error messages
                if any(error in response.text.lower() for error in 
                    ['sql', 'mysql', 'sqlite', 'postgresql', 'oracle']):
                    self.report_vulnerability({
                        'type': 'SQL Injection',
                        'url': url,
                        'parameter': param,
                        'payload': payload
                    })

        except Exception as e:
            print(f"Error testing SQL injection on {url}: {str(e)}")

def check_xss(self, url: str) -> None:
    """Test for potential Cross-Site Scripting vulnerabilities"""
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')"
    ]

    for payload in xss_payloads:
        try:
            # Test GET parameters
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)

            for param in params:
                test_url = url.replace(f"{param}={params[param][0]}", 
                                     f"{param}={urllib.parse.quote(payload)}")
                response = self.session.get(test_url)

                if payload in response.text:
                    self.report_vulnerability({
                        'type': 'Cross-Site Scripting (XSS)',
                        'url': url,
                        'parameter': param,
                        'payload': payload
                    })

        except Exception as e:
            print(f"Error testing XSS on {url}: {str(e)}")

def check_sensitive_info(self, url: str) -> None:
    """Check for exposed sensitive information"""
    sensitive_patterns = {
        'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
        'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
        'api_key': r'api[_-]?key[_-]?([\'"|`])([a-zA-Z0-9]{32,45})\1'
    }

    try:
        response = self.session.get(url)

        for info_type, pattern in sensitive_patterns.items():
            matches = re.finditer(pattern, response.text)
            for match in matches:
                self.report_vulnerability({
                    'type': 'Sensitive Information Exposure',
                    'url': url,
                    'info_type': info_type,
                    'pattern': pattern
                })

    except Exception as e:
        print(f"Error checking sensitive information on {url}: {str(e)}")


def scan(self) -> List[Dict]:
    """
    Main scanning method that coordinates the security checks

    Returns:
        List of discovered vulnerabilities
    """
    print(f"\n{colorama.Fore.BLUE}Starting security scan of {self.target_url}{colorama.Style.RESET_ALL}\n")

    # First, crawl the website
    self.crawl(self.target_url)

    # Then run security checks on all discovered URLs
    with ThreadPoolExecutor(max_workers=5) as executor:
        for url in self.visited_urls:
            executor.submit(self.check_sql_injection, url)
            executor.submit(self.check_xss, url)
            executor.submit(self.check_sensitive_info, url)

    return self.vulnerabilities

def report_vulnerability(self, vulnerability: Dict) -> None:
    """Record and display found vulnerabilities"""
    self.vulnerabilities.append(vulnerability)
    print(f"{colorama.Fore.RED}[VULNERABILITY FOUND]{colorama.Style.RESET_ALL}")
    for key, value in vulnerability.items():
        print(f"{key}: {value}")
    print()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python scanner.py <target_url>")
        sys.exit(1)

    target_url = sys.argv[1]
    scanner = WebSecurityScanner(target_url)
    vulnerabilities = scanner.scan()

    # Print summary
    print(f"\n{colorama.Fore.GREEN}Scan Complete!{colorama.Style.RESET_ALL}")
    print(f"Total URLs scanned: {len(scanner.visited_urls)}")
    print(f"Vulnerabilities found: {len(vulnerabilities)}")