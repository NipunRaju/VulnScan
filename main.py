from flask import Flask, request, render_template
import subprocess
import re

app = Flask(__name__)

def run_script(script_name, *args):
    result = subprocess.run(['python', script_name, *args], capture_output=True, text=True)
    return result.stdout

def extract_host(url):
    pattern = r'^(?:http[s]?://)?([^:/\s]+)'
    match = re.search(pattern, url)
    if match:
        return match.group(1)
    return url

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    url = request.form['url']
    choice = request.form['choice']
    host = extract_host(url)
    ports = "80,443,22,21"
    credentials = "admin:admin,admin:password,test:test"

    output = ""
    if choice == "1":
        output = f'<p class="blue">Scanning open ports on {host}...</p>\n' + \
                 f'<p class="blue">{run_script("port_scan.py", host, ports)}</p>'
    elif choice == "2":
        output = f'<p class="green">SQL Injection vulnerability:</p>\n' + \
                 f'<p class="green">{run_script("sql_injection.py", url)}</p>'
    elif choice == "3":
        output = f'<p class="red">XSS vulnerability:</p>\n' + \
                 f'<p class="red">{run_script("xss.py", url)}</p>'
    elif choice == "4":
        output = f'<p class="purple">Directory Traversal vulnerability:</p>\n' + \
                 f'<p class="purple">{run_script("directory_traversal.py", url)}</p>'
    elif choice == "5":
        output = f'<p class="orange">Security headers:</p>\n' + \
                 f'<p class="orange">{run_script("security_headers.py", url)}</p>'
    elif choice == "6":
        output = f'<p class="cyan">Outdated software:</p>\n' + \
                 f'<p class="cyan">{run_script("outdated_software.py", url)}</p>'
    elif choice == "7":
        output = f'<p class="magenta">Subdomains enumeration for {host}:</p>\n' + \
                 f'<p class="magenta">{run_script("subdomain_enumeration.py", host)}</p>'
    elif choice == "8":
        output = f'<p class="yellow">Brute force directories:</p>\n' + \
                 f'<p class="yellow">{run_script("brute_force_directories.py", url)}</p>'
    elif choice == "9":
        output = f'<p class="brown">SSL certificate information for {host}:</p>\n' + \
                 f'<p class="brown">{run_script("ssl_certificate.py", host)}</p>'
    elif choice == "10":
        output = f'<p class="lime">Weak password detection for {url}:</p>\n' + \
                 f'<p class="lime">{run_script("weak_password.py", url, credentials)}</p>'
    elif choice == "11":
        output = f'<p class="blue">Scanning open ports on {host}...</p>\n' + \
                 f'<p class="blue">{run_script("port_scan.py", host, ports)}</p>\n' + \
                 f'<p class="green">SQL Injection vulnerability:</p>\n' + \
                 f'<p class="green">{run_script("sql_injection.py", url)}</p>\n' + \
                 f'<p class="red">XSS vulnerability:</p>\n' + \
                 f'<p class="red">{run_script("xss.py", url)}</p>\n' + \
                 f'<p class="purple">Directory Traversal vulnerability:</p>\n' + \
                 f'<p class="purple">{run_script("directory_traversal.py", url)}</p>\n' + \
                 f'<p class="orange">Security headers:</p>\n' + \
                 f'<p class="orange">{run_script("security_headers.py", url)}</p>\n' + \
                 f'<p class="cyan">Outdated software:</p>\n' + \
                 f'<p class="cyan">{run_script("outdated_software.py", url)}</p>\n' + \
                 f'<p class="magenta">Subdomains enumeration for {host}:</p>\n' + \
                 f'<p class="magenta">{run_script("subdomain_enumeration.py", host)}</p>\n' + \
                 f'<p class="yellow">Brute force directories:</p>\n' + \
                 f'<p class="yellow">{run_script("brute_force_directories.py", url)}</p>\n' + \
                 f'<p class="brown">SSL certificate information for {host}:</p>\n' + \
                 f'<p class="brown">{run_script("ssl_certificate.py", host)}</p>\n' + \
                 f'<p class="lime">Weak password detection for {url}:</p>\n' + \
                 f'<p class="lime">{run_script("weak_password.py", url, credentials)}</p>'

    return render_template('index.html', output=output)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

