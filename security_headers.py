import requests

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

if __name__ == "__main__":
    import sys
    url = sys.argv[1]
    headers = check_security_headers(url)
    for header, value in headers.items():
        print(f"{header}: {value}")
