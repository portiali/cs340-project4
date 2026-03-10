import sys
import time
import json
import subprocess
import requests
import socket
import urllib
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

TLS_FLAGS = {
    "SSLv2": "-ssl2",
    "SSLv3": "-ssl3",
    "TLSv1.0": "-tls1",
    "TLSv1.1": "-tls1_1",
    "TLSv1.2": "-tls1_2",
    "TLSv1.3": "-tls1_3"
}

def get_ip(domain, type):
    '''
    Uses subprocess to retrieve all ipv4 addresses tied with the domain using the global DNS
    '''
    ips = set()
    for resolver in DNS_RESOLVERS:
        try:
            if type == "ipv4":
                lookup = subprocess.check_output(["nslookup", "-type=A", domain, resolver], timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
                # print(lookup)
            elif type == "ipv6":
                lookup = subprocess.check_output(["nslookup","-type=AAAA", domain, resolver], timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
                # print(lookup)
        except subprocess.TimeoutExpired:
            print(f"Timeout querying {resolver}", file=sys.stderr)
            continue        
        #parses for ipv4 in the response
        responses = lookup.splitlines()
        # print(responses)
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
    
def check_insecure_http(domain):
    try:
        s = socket.create_connection((domain, 80), timeout=2)
        s.close()
        return True
    except:
        return False
#check redirects with requests lib
def check_redirect(domain):
    url = f"http://{domain}"
    for i in range(10):
        # print('current url: ', url)
        r = requests.get(url, timeout=2, allow_redirects=False)
        if not (300 <= r.status_code < 400):
            break
        new_url = r.headers.get("Location")
        if not new_url:
            break
        url = urllib.parse.urljoin(url, new_url)
    return url.startswith("https")

def check_hsts(domain):
    try:
        r = requests.get(f"http://{domain}", timeout=2)
        return "Strict-Transport-Security" in r.headers
    except requests.RequestException:
        return False

def get_tls_versions(domain):
    support = []
    for tls, flag in TLS_FLAGS.items():
        try:
            # print('FLAG: ', flag)
            output = subprocess.check_output(
                ["openssl", "s_client", flag, "-connect", f"{domain}:443"],
                input=b"",
                stderr=subprocess.STDOUT,
                timeout=2
            ).decode("utf-8")
            # print(output)
            if "Cipher is" in output:
                support.append(tls)
        except:
            continue
    return support

def get_root_ca(domain):
    try:
        output = subprocess.check_output(
            ["openssl", "s_client", "-connect", f"{domain}:443"],
            input=b"",
            stderr=subprocess.STDOUT,
            timeout=2
        ).decode("utf-8")
        # print(output)
        lines = output.splitlines()
        max_depth = -1
        root_line = None
        for line in lines:
            if line.startswith("depth=") and "O =" in line:
                depth = int(line.split("=")[1].split()[0])
                if depth > max_depth:
                    root_line = line
                    max_depth = depth
        # print(root_line)
        root_ca = root_line.split(",")[1].split("=")[1].strip()
        return root_ca
    except:
        return None    
            

def get_rdns_names(ips):
    reverse_names = set()
    try:
        for ip in ips:
            lookup = subprocess.check_output(["nslookup", "-type=PTR", ip, "8.8.8.8"], timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
            # print(lookup)
            lines = lookup.splitlines()
            
            if not lines:
                continue
            
            for line in lines:
                if ".in-addr.arpa" in line:
                    # print(line)
                    addr = line.split('=')[1].strip().rstrip(".")
                    reverse_names.add(addr)
        return list(reverse_names)
    except:
        return []

def get_rtt(ips):
    min_t, max_t = float('inf'), float('-inf')
    try:
        for ip in ips:
            cmd = f"sh -c \"time echo -e '\\x1dclose\\x0d' | telnet {ip} 443\""
            result = subprocess.check_output(
                cmd,
                shell=True,
                stderr=subprocess.STDOUT,
                timeout=5
            ).decode()
            lines = result.splitlines()
            
            for line in lines:
                if line.startswith('real'):
                    minutes, secs = line.split()[1].split("m")
                    minutes = float(minutes)
                    secs = float(secs[:-1])
                    total = int((60*minutes + secs)*1000)
                    min_t = min(min_t, total)
                    max_t = max(max_t, total)
        return [min_t, max_t] if min_t != float('inf') and max_t != float('-inf') else None
    except FileNotFoundError:
        print('telnet command not found, skipping RTT!', file=sys.stderr)
        return None


def scan_domain(domain_list):
    '''
    Calls each individual scanner to retrieve information about each domain
    '''
    results = {}
    for domain in domain_list:
        results[domain] = {}
        # results[domain]['scan_time'] = time.time()
        results[domain]['ipv4_addresses'] = get_ip(domain, "ipv4")
        # results[domain]['ipv6_addresses'] = get_ip(domain, "ipv6")
        # results[domain]['Server'] = get_http_server(domain)
        # results[domain]['insecure_http'] = check_insecure_http(domain)
        # results[domain]['redirect_to_https'] = check_redirect(domain)
        # results[domain]['hsts'] = check_hsts(domain)
        # results[domain]['tls_versions'] = get_tls_versions(domain)
        # results[domain]['root_ca'] = get_root_ca(domain)
        # results[domain]['rdns_names'] = get_rdns_names(results[domain]['ipv4_addresses'])
        
        
        rtts = get_rtt(results[domain]['ipv4_addresses'])
        if rtts:
            results[domain]['rtt_range'] = rtts

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