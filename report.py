
import texttable
import json
import sys
from collections import Counter

'''
Requirements:
A textual or tabular listing of all the information returned in Part 2, with a section for each domain.
A table showing the RTT ranges for all domains, sorted by the minimum RTT (ordered from fastest to slowest).
A table showing the number of occurrences for each observed root certificate authority (from Part 2i), sorted from most popular to least.
A table showing the number of occurrences of each web server (from Part 2d), ordered from most popular to least.
A table showing the percentage of scanned domains supporting:
each version of TLS listed in Part 2h. I expect to see close to zero percent for SSLv2 and SSLv3.
"plain http" (Part 2e)
"https redirect" (Part 2f)
"hsts" (Part 2g)
"ipv6" (from Part 2c)
'''


def build_table(out, data):
    table = texttable.Texttable()

    table.add_rows([
    ["Domain","Server","HSTS","HTTP","HTTPS Redirect","IPv6","Root CA","RTT Min","RTT Max"]
    ])
    table.set_max_width(200)
    for domain, info in data.items():
        table.add_row([
            domain,
            info["Server"],
            info["hsts"],
            info["insecure_http"],
            info["redirect_to_https"],
            len(info["ipv6_addresses"]) > 0,
            info["root_ca"],
            info["rtt_range"][0],
            info["rtt_range"][1]
        ])

    out.write("DOMAIN SUMMARY\n")
    out.write(table.draw() + "\n\n")

    table = texttable.Texttable()


    table.add_rows([["Domain","Min RTT","Max RTT"]])

    sorted_domains = sorted(
        data.items(),
        key=lambda x: x[1]["rtt_range"][0]
    )

    for domain, info in sorted_domains:
        table.add_row([
            domain,
            info["rtt_range"][0],
            info["rtt_range"][1]
        ])

    out.write("RTT RANGES (FASTEST → SLOWEST)\n")
    out.write(table.draw() + "\n\n")

    ca_counter = Counter()
    for info in data.values():
        ca_counter[info["root_ca"]] += 1

    table = texttable.Texttable()
    table.add_rows([["Root CA","Count"]])

    for ca, count in ca_counter.most_common():
        table.add_row([ca, count])

    out.write("ROOT CERTIFICATE AUTHORITIES\n")
    out.write(table.draw() + "\n\n")

    server_counter = Counter()

    for info in data.values():
        server = info["Server"] if info["Server"] else "Unknown"
        server_counter[server] += 1

    table = texttable.Texttable()
    table.add_rows([["Web Server","Count"]])

    for server, count in server_counter.most_common():
        table.add_row([server, count])

    out.write("WEB SERVER POPULARITY\n")
    out.write(table.draw() + "\n\n")


    tls_versions = [
    "SSLv2","SSLv3","TLSv1.0","TLSv1.1","TLSv1.2","TLSv1.3"
    ]

    tls_counts = {v:0 for v in tls_versions}

    for info in data.values():
        for v in info["tls_versions"]:
            if v in tls_counts:
                tls_counts[v] += 1

    total = len(data)

    table = texttable.Texttable()
    table.add_rows([["Protocol","% Support"]])

    for v in tls_versions:
        percent = (tls_counts[v] / total) * 100
        table.add_row([v, f"{percent:.2f}%"])

    out.write("TLS SUPPORT\n")
    out.write(table.draw() + "\n\n")


    http = 0
    redirect = 0
    hsts = 0
    ipv6 = 0

    for info in data.values():
        if info["insecure_http"]:
            http += 1
        if info["redirect_to_https"]:
            redirect += 1
        if info["hsts"]:
            hsts += 1
        if len(info["ipv6_addresses"]) > 0:
            ipv6 += 1

    table = texttable.Texttable()
    table.add_rows([
    ["Feature","% Support"],
    ["Plain HTTP", f"{http/total*100:.2f}%"],
    ["HTTPS Redirect", f"{redirect/total*100:.2f}%"],
    ["HSTS", f"{hsts/total*100:.2f}%"],
    ["IPv6", f"{ipv6/total*100:.2f}%"]
    ])

    out.write("FEATURE SUPPORT\n")
    out.write(table.draw() + "\n\n")

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
        results = json.load(f)
    # print(results)
    
    out = open(output_file, "w")
    build_table(out, results)
    out.close()


if __name__ == "__main__":
    main()