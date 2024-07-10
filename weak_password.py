import requests

def weak_password_detection(base_url, credentials):
    vulnerable_credentials = []
    login_url = f"{base_url}/userinfo.php"
    
    for username, password in credentials:
        response = requests.post(login_url, data={'uname': username, 'pass': password})
        
        # Check if response indicates a successful login
        if response.status_code == 200:
            if "Logout" in response.text or "Welcome" in response.text or "User Info" in response.text:
                vulnerable_credentials.append((username, password))
            else:
                print(f"Login failed for {username}/{password}")
        elif response.status_code == 401:
            print(f"Unauthorized for {username}/{password}")
        else:
            print(f"Unexpected status code {response.status_code} for {username}/{password}")
            
    return vulnerable_credentials

if __name__ == "__main__":
    import sys
    base_url = sys.argv[1]
    credentials = [cred.split(':') for cred in sys.argv[2].split(',')]
    vulnerable_credentials = weak_password_detection(base_url, credentials)
    if vulnerable_credentials:
        for username, password in vulnerable_credentials:
            print(f"Vulnerable credentials: {username}/{password}")
    else:
        print("No weak credentials detected")
