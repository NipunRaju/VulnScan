import subprocess

def port_scan(host, ports):
    try:
        # Convert the list of ports to a comma-separated string
        ports_str = ','.join(map(str, ports))
        # Use the full path to nmap executable
        nmap_path = r"C:\Program Files (x86)\Nmap\nmap.exe"
        result = subprocess.run(
            [nmap_path, "-p", ports_str, host],
            capture_output=True,
            text=True
        )
        return result.stdout
    except Exception as e:
        return f"An error occurred: {e}"

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: python port_scan.py <host> <ports>")
        sys.exit(1)
    host = sys.argv[1]
    ports = list(map(int, sys.argv[2].split(',')))
    print(port_scan(host, ports))
