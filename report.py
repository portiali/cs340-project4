
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
    ["Domain","Server","Geolocation", "Scan Time", "HSTS","HTTP","HTTPS Redirect","IPv4", "IPv6","TLS", "RDNS Names", "Root CA","RTT Min","RTT Max"]
    ])
    table.set_max_width(200)
    #add all information to a table 
    for domain, info in data.items():
        geoloc = str(info["geo_locations"]) if len(info["geo_locations"])> 0 else "None"
        ipv4 = "\n".join(info["ipv4_addresses"])
        ipv6 = "\n".join(info["ipv6_addresses"]) if len(info["ipv6_addresses"])>0 else "None"
        tls = "\n".join(info["tls_versions"]) if len(info["tls_versions"])>0 else "None"
        scan_time = info["scan_time"]
        rdns_names = "\n".join(info["rdns_names"]) if len(info["rdns_names"])>0 else "None"

        table.add_row([
            domain,
            info["Server"],
            geoloc,
            scan_time,
            info["hsts"],
            info["insecure_http"],
            info["redirect_to_https"],
            ipv4,
            ipv6,
            tls,
            rdns_names,
            info["root_ca"],
            info["rtt_range"][0],
            info["rtt_range"][1]
        ])

    out.write("(1) DOMAIN SUMMARY\n")
    out.write(table.draw() + "\n\n")

    table = texttable.Texttable()


    table.add_rows([["Domain","Min RTT","Max RTT"]])
    #sort by min rtt
    sorted_domains = sorted(
        data.items(),
        key=lambda x: x[1]["rtt_range"][0]
    )
    #add rows for each domain's rtt
    for domain, info in sorted_domains:
        table.add_row([
            domain,
            info["rtt_range"][0],
            info["rtt_range"][1]
        ])

    out.write("(2) RTT RANGES (FASTEST to SLOWEST)\n")
    out.write(table.draw() + "\n\n")

    #perform counting for each root cert authority
    ca_counter = Counter()
    for info in data.values():
        ca_counter[info["root_ca"]] += 1

    table = texttable.Texttable()
    table.add_rows([["Root CA","Occurrence Count"]])

    for ca, count in ca_counter.most_common():
        table.add_row([ca, count])

    out.write("(3) ROOT CERTIFICATE AUTHORITIES\n")
    out.write(table.draw() + "\n\n")

    server_counter = Counter()
    #perform counting for each distinct web server
    for info in data.values():
        server = info["Server"] if info["Server"] else "Unknown Web Server"
        server_counter[server] += 1

    table = texttable.Texttable()
    table.add_rows([["Web Server","Occurrence Count"]])

    for server, count in server_counter.most_common():
        table.add_row([server, count])

    out.write("(4) WEB SERVER POPULARITY\n")
    out.write(table.draw() + "\n\n")


    #perform counting for each tls version within each object
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

    for v in tls_versions:
        percent = (tls_counts[v] / total) * 100
        table.add_row([v, f"{percent:.2f}%"])

    #perform counting for each feature mentioned in p5 within each object
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

    table.add_rows([
    ["Feature","% Support"],
    ["Plain HTTP", f"{http/total*100:.2f}%"],
    ["HTTPS Redirect", f"{redirect/total*100:.2f}%"],
    ["HSTS", f"{hsts/total*100:.2f}%"],
    ["IPv6", f"{ipv6/total*100:.2f}%"]
    ])


    out.write("(5) PERCENTAGE SUPPORTED\n")
    out.write(table.draw() + "\n\n")



def main():
    '''
    Takes in user input for a json containing domain information to scan
    Writes to a text file summarizing each feature
    '''
    if len(sys.argv) != 3:
        print(f"Usage: python3 {sys.argv[0]} <input_file.json> <output_file.txt>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
   #opens json containing all scanned information
    with open(input_file, 'r') as f:
        results = json.load(f)
    # print(results)
    
    #writes to output file
    out = open(output_file, "w")
    build_table(out, results)
    out.close()


if __name__ == "__main__":
    main()