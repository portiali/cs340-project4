import sys
import time
import json
import subprocess
import requests

#these use all the dns resolvers
# DNS_RESOLVERS = ["208.67.222.222",
# "1.1.1.1",
# "8.8.8.8",
# "8.26.56.26",
# "9.9.9.9",
# "94.140.14.14",
# "185.228.168.9",
# "76.76.2.0",
# "76.76.19.19",
# "129.105.49.1",
# "74.82.42.42",
# "205.171.3.65",
# "193.110.81.0",
# "147.93.130.20",
# "51.158.108.203"]

#picked out a subset of dns resolvers for shorter run time
DNS_RESOLVERS = [
    "208.67.222.222",
    "1.1.1.1",
    "8.8.8.8",
    "9.9.9.9"
]
def get_ip(domain, type):
    '''
    Uses subprocess to retrieve all ipv4 addresses tied with the domain using the global DNS
    '''
    ips = set()
    for resolver in DNS_RESOLVERS:
        try:
            if type == "ipv4":
                lookup = subprocess.check_output(["nslookup", domain, resolver], timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
            elif type == "ipv6":
                lookup = subprocess.check_output(["nslookup","-type=AAAA", domain, resolver], timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
                # print(lookup)
        except subprocess.TimeoutExpired:
            print(f"Timeout querying {resolver}", file=sys.stderr)
            continue        
        #parses for ipv4 in the response
        responses = lookup.splitlines()
        if not responses:
            return []
        answer = False
        for line in responses:
            if "answer" in line.lower():
                answer = True
                continue

            if answer:
                if "Address:" in line:
                    ip = line.split("Address:")[1].strip()
                    ips.add(ip)

                elif "AAAA address" in line:
                    ip = line.split("AAAA address")[1].strip()
                    ips.add(ip)
    return list(ips)
    
def get_http_server(domain):
    response = requests.get(f"https://{domain}")
    headers = response.headers
    if "Server" in headers:
        return headers["Server"]
    return None
    


def scan_domain(domain_list):
    '''
    Calls each individual scanner to retrieve information about each domain
    '''
    results = {}
    for domain in domain_list:
        results[domain] = {}
        results[domain]['scan_time'] = time.time()
        results[domain]['ipv4_addresses'] = get_ip(domain, "ipv4")
        results[domain]['ipv6_addresses'] = get_ip(domain, "ipv6")
        results[domain]['Server'] = get_http_server(domain)
    return results



def main():
    '''
    Takes in user input for an input file containing domains to scan
    Outputs and saves a json dictionary containing information about each domain
    '''
    if len(sys.argv) != 3:
        print(f"Usage: python3 {sys.argv[0]} <input_file.txt> <output_file.json>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    # open the input file and grab each domain name
    with open(input_file, 'r') as f:
        domain_list = f.read().splitlines()

    results = scan_domain(domain_list)

    
    with open(output_file, 'w') as f:
        json.dump(results, f, sort_keys=True, indent=4)
    return results

if __name__ == "__main__":
    main()