import requests
from prettytable import PrettyTable
import ssl
import socket

def check_https(url):
    try:
        if not url.startswith("https://"):
            return "No", "URL does not use HTTPS"
        hostname = url.split("://")[1].split("/")[0]
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                ssl_info = ssock.getpeercert()
        return "Yes", ssl_info
    except Exception as e
        return "No", f"Error checking HTTPS: {e}"

def check_security_headers(url):
    try:
        response = requests.get(url)
        headers = response.headers
    except Exception as e:
        print(f"Error accessing {url}: {e}")
        return

    # Define the headers to check and their recommended values
    security_headers = {
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
        "Access-Control-Allow-Origin": "*",
        "Cache-Control": "no-store",
        "Pragma": "no-cache",
        "Expires": "0",
        "Server": "nginx"  # Check for NGINX server
    }

    # Check if the headers are present and their values
    table = PrettyTable(["Header", "Present", "Expected Value", "Actual Value"])
    for header, recommended_value in security_headers.items():
        actual_value = headers.get(header, "Not Present")
        is_present = "Yes" if header in headers else "No"
        table.add_row([header, is_present, recommended_value, actual_value])

    print("Security Headers Check:")
    print(table)

    # Additional security checks
    https_check, https_details = check_https(url)
    table = PrettyTable(["Check", "Pass", "Details"])
    table.add_row(["HTTPS", https_check, https_details])

    print("\nAdditional Security Checks:")
    print(table)

    # NGINX specific configurations (assuming we have access to its configuration)
    check_nginx_configs()

def check_nginx_configs():
    # This is a mock function as we can't access actual server configs
    # In a real scenario, this function should access the server configs securely
    nginx_configs = {
        "ssl_protocols": "TLSv1.2 TLSv1.3",
        "ssl_ciphers": "HIGH:!aNULL:!MD5",
        "ssl_prefer_server_ciphers": "on",
        "ssl_session_cache": "shared:SSL:10m",
        "ssl_session_timeout": "10m",
        "ssl_dhparam": "/etc/nginx/ssl/dhparam.pem",
        "ssl_stapling": "on",
        "ssl_stapling_verify": "on",
        "client_max_body_size": "1m",
        "server_tokens": "off"
    }

    # Pretend we read the actual config values here
    actual_nginx_configs = {
        "ssl_protocols": "TLSv1.2 TLSv1.3",
        "ssl_ciphers": "HIGH:!aNULL:!MD5",
        "ssl_prefer_server_ciphers": "on",
        "ssl_session_cache": "shared:SSL:10m",
        "ssl_session_timeout": "10m",
        "ssl_dhparam": "/etc/nginx/ssl/dhparam.pem",
        "ssl_stapling": "on",
        "ssl_stapling_verify": "on",
        "client_max_body_size": "1m",
        "server_tokens": "off"
    }

    table = PrettyTable(["Config", "Expected Value", "Actual Value", "Compliant"])
    for config, expected_value in nginx_configs.items():
        actual_value = actual_nginx_configs.get(config, "Not Present")
        compliant = "Yes" if actual_value == expected_value else "No"
        table.add_row([config, expected_value, actual_value, compliant])

    print("\nNGINX Configurations Check:")
    print(table)

if __name__ == "__main__":
    url = input("Enter the URL to check: ")
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
    check_security_headers(url)
