import socket
import ssl
import datetime

def check_ssl_certificate(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cert_expiry = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                cert_valid = cert_expiry > datetime.datetime.now()
                return cert_valid, cert_expiry
    except ssl.SSLError as e:
        print(f"SSL Error occurred: {e}")
    except socket.error as e:
        print(f"Socket Error occurred: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

    # Return None or appropriate defaults if certificate retrieval fails
    return False, None

if __name__ == "__main__":
    import sys
    domain = sys.argv[1]
    cert_valid, cert_expiry = check_ssl_certificate(domain)
    if cert_valid:
        print(f"SSL certificate valid until: {cert_expiry}")
    else:
        print("SSL certificate not valid or could not be retrieved.")
