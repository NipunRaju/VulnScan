import requests
import sys

def brute_force_directories(url):
    wordlist = [
        "admin",
        "login",
        "wp-admin",
        "wp-login.php",
        "test",
        "config",
        "secret",
        "backup",
        "phpmyadmin/setup",
        "phpmyadmin",
        "mysql",
        "webmail",
        "admin_area",
        "siteadmin",
        "admin_console",
        "uploads",
        "images",
        "downloads",
        "search",
        "api",
        "rest",
        "v1",
        "auth",
        "admin_login",
        "adminpanel",
        "login.php",
        "register",
        "signup",
        "profile",
        "reset_password",
        "forgot_password",
        "reset",
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

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python brute_force_directories.py <url>")
        sys.exit(1)
    
    url = sys.argv[1]
    discovered_paths = brute_force_directories(url)
    for path in discovered_paths:
        print(path)
