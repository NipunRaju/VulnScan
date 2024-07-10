import requests
import sys
import json

def get_server_info(url):
    try:
        response = requests.get(url)
        server_header = response.headers.get('Server', '')
        return server_header
    except requests.RequestException as e:
        print(f"Error fetching the URL: {e}")
        sys.exit(1)

def extract_software_and_version(server_header):
    if 'Apache' in server_header:
        software = 'Apache'
        version = server_header.split('Apache/')[1].split(' ')[0]
    elif 'nginx' in server_header:
        software = 'nginx'
        version = server_header.split('nginx/')[1].split(' ')[0]
    else:
        software = None
        version = None
    return software, version

def get_cpe_name(software, version):
    cpe_names = {
        'Apache': f'cpe:2.3:a:apache:http_server:{version}:*:*:*:*:*:*:*',
        'nginx': f'cpe:2.3:a:nginx:nginx:{version}:*:*:*:*:*:*:*'
    }
    return cpe_names.get(software)

def check_nvd_for_vulnerabilities(cpe_name):
    nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe_name}"
    try:
        response = requests.get(nvd_url)
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get('result', {}).get('CVE_Items', [])
            return nvd_url, data, vulnerabilities
        else:
            print(f"Failed to fetch data from NVD. Status code: {response.status_code}")
            return nvd_url, {}, []
    except requests.RequestException as e:
        print(f"Error fetching the NVD data: {e}")
        sys.exit(1)

def format_vulnerability(vulnerability):
    cve_id = vulnerability.get('cve', {}).get('CVE_data_meta', {}).get('ID', 'N/A')
    description = vulnerability.get('cve', {}).get('description', {}).get('description_data', [{}])[0].get('value', 'No description available')
    references = [ref.get('url', 'No URL available') for ref in vulnerability.get('references', {}).get('reference_data', [])]
    ref_urls = ', '.join(references)
    return f"- {cve_id}: {description} [References: {ref_urls}]"

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python check_server_vulnerabilities.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    server_header = get_server_info(url)
    print(f"Server Header: {server_header}")

    software, version = extract_software_and_version(server_header)
    if software and version:
        print(f"Detected Software: {software} {version}")
        cpe_name = get_cpe_name(software, version)
        if cpe_name:
            api_url, api_response, vulnerabilities = check_nvd_for_vulnerabilities(cpe_name)
            print(f"NVD API URL: {api_url}")
            print("NVD API Response:")
            print(json.dumps(api_response, indent=4))

            if vulnerabilities:
                print(f"Found {len(vulnerabilities)} vulnerabilities for {software} {version}:")
                for vulnerability in vulnerabilities:
                    formatted_vuln = format_vulnerability(vulnerability)
                    print(formatted_vuln)
            else:
                print(f"No known vulnerabilities found for {software} {version}.")
        else:
            print(f"CPE name not found for {software} {version}.")
    else:
        print("No supported software detected in the server header.")

