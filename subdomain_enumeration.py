import dns.resolver

def subdomain_enumeration(domain):
    subdomains = ['www', 'mail', 'ftp', 'localhost', 'webmail', 'server']
    found_subdomains = []
    for subdomain in subdomains:
        try:
            full_domain = f"{subdomain}.{domain}"
            answers = dns.resolver.resolve(full_domain, 'A')
            found_subdomains.append(full_domain)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout) as e:
            print(f"Subdomain not found or no answer for {full_domain}: {e}")
        except Exception as e:
            print(f"An error occurred while resolving {full_domain}: {e}")
    return found_subdomains

if __name__ == "__main__":
    import sys
    domain = sys.argv[1]
    subdomains = subdomain_enumeration(domain)
    if subdomains:
        print("Found subdomains:")
        for subdomain in subdomains:
            print(f" - {subdomain}")
    else:
        print("No subdomains found")
