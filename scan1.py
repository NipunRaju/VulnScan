import socket
import requests
import dns.resolver
import ssl
import datetime
from requests.auth import HTTPBasicAuth

def scan_ports(host, ports):
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

def check_sql_injection(url):
    payload = "' OR '1'='1"
    test_url = f"{url}?q={payload}"
    response = requests.get(test_url)
    if "syntax error" in response.text or "mysql" in response.text.lower():
        return True
    return False

def check_xss(url):
    payload = "<script>alert('xss')</script>"
    test_url = f"{url}?q={payload}"
    response = requests.get(test_url)
    if payload in response.text:
        return True
    return False

def check_directory_traversal(url):
    payload = "../../../../../../etc/passwd"
    test_url = f"{url}/{payload}"
    response = requests.get(test_url)
    if "root:x:" in response.text:
        return True
    return False

def check_security_headers(url):
    response = requests.get(url)
    headers = response.headers
    security_headers = {
        'Content-Security-Policy': headers.get('Content-Security-Policy', 'Missing'),
        'X-Content-Type-Options': headers.get('X-Content-Type-Options', 'Missing'),
        'X-Frame-Options': headers.get('X-Frame-Options', 'Missing'),
        'Strict-Transport-Security': headers.get('Strict-Transport-Security', 'Missing')
    }
    return security_headers

def check_outdated_software(url):
    response = requests.get(url)
    server_header = response.headers.get('Server', '')
    known_vulnerable_versions = {
        'Apache': '2.4.49',  # Example vulnerable version
        'nginx': '1.20.1',   # Example vulnerable version
    }

    for software, version in known_vulnerable_versions.items():
        if software in server_header and version in server_header:
            return True, server_header
    return False, server_header

def subdomain_enumeration(domain):
    subdomains = ['www', 'mail', 'ftp', 'localhost', 'webmail', 'server']
    found_subdomains = []
    for subdomain in subdomains:
        try:
            full_domain = f"{subdomain}.{domain}"
            answers = dns.resolver.resolve(full_domain, 'A')
            found_subdomains.append(full_domain)
        except dns.resolver.NXDOMAIN:
            continue
    return found_subdomains

def brute_force_directories(url):
    wordlist = [
        "admin",
        "login",
        "wp-admin",
        "wp-login.php",
        "test",
        "config",
        "secret",
        "backup"
    ]
    
    discovered_paths = []
    for path in wordlist:
        test_url = f"{url}/{path}"
        response = requests.get(test_url)
        if response.status_code == 200:
            discovered_paths.append(test_url)
            print(f"Discovered: {test_url}")
        elif response.status_code == 403:
            print(f"Forbidden: {test_url}")
        elif response.status_code == 401:
            print(f"Unauthorized: {test_url}")
        elif response.status_code == 404:
            print(f"Not Found: {test_url}")
        else:
            print(f"Unexpected Status ({response.status_code}): {test_url}")
    return discovered_paths

def check_ssl_certificate(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cert_expiry = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                cert_valid = cert_expiry > datetime.datetime.now()
                return cert_valid, cert_expiry
    except ssl.SSLError as e:
        print(f"SSL Error occurred: {e}")
    except socket.error as e:
        print(f"Socket Error occurred: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

    # Return None or appropriate defaults if certificate retrieval fails
    return False, None

def weak_password_detection(url, credentials):
    vulnerable_credentials = []
    for username, password in credentials:
        response = requests.get(url, auth=HTTPBasicAuth(username, password))
        if response.status_code == 200:
            vulnerable_credentials.append((username, password))
    return vulnerable_credentials

def main():
    # Prompt user for URL input
    url = input("Enter the URL to scan (e.g., http://example.com): ").strip()

    host = url.split('//')[1] if '//' in url else url.split('/')[0]

    ports = [80, 443, 22, 21]  # Common ports to check
    
    print(f"\nScanning open ports on {host}...")
    open_ports = scan_ports(host, ports)
    print(f"Open ports: {open_ports}\n")

    print(f"Checking vulnerabilities for {url}:\n")

    print(f"1. SQL Injection vulnerability:")
    vulnerable_to_sql_injection = check_sql_injection(url)
    print(f"   - Vulnerable: {vulnerable_to_sql_injection}\n")

    print(f"2. XSS vulnerability:")
    vulnerable_to_xss = check_xss(url)
    print(f"   - Vulnerable: {vulnerable_to_xss}\n")

    print(f"3. Directory Traversal vulnerability:")
    vulnerable_to_directory_traversal = check_directory_traversal(url)
    print(f"   - Vulnerable: {vulnerable_to_directory_traversal}\n")

    print(f"4. Security headers:")
    security_headers = check_security_headers(url)
    for header, value in security_headers.items():
        print(f"   - {header}: {value}")
    print()

    print(f"5. Outdated software:")
    outdated_software, server_header = check_outdated_software(url)
    print(f"Server header: {server_header}")
    print(f"   - Outdated: {outdated_software}")
    if outdated_software:
        print(f"     Server header: {server_header}")
    print()

    print(f"6. Subdomains enumeration for {host}:")
    subdomains = subdomain_enumeration(host)
    if subdomains:
        for subdomain in subdomains:
            print(f"   - {subdomain}")
    else:
        print("   - No subdomains found")
    print()

    discovered_paths = brute_force_directories(url)

    print("\nDiscovered paths:")
    for path in discovered_paths:
        print(path)

    print(f"8. SSL certificate information for {host}:")
    cert_valid, cert_expiry = check_ssl_certificate(url)

    if cert_valid:
        print(f"SSL certificate valid until: {cert_expiry}")
    else:
        print("SSL certificate not valid or could not be retrieved.")

    credentials = [('admin', 'admin'), ('admin', 'password'), ('test', 'test')]  # Example credentials
    print(f"9. Weak password detection for {url}:")
    weak_passwords = weak_password_detection(url, credentials)
    if weak_passwords:
        for username, password in weak_passwords:
            print(f"   - Vulnerable credentials: {username}/{password}")
    else:
        print("   - No weak credentials detected")

if __name__ == "__main__":
    main()
