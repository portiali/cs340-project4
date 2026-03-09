import sys
import time
import json
import subprocess
# Part 1: Scanner Framework

# takes a list of web domains as an input and outputs a JSON dict with info about each domain
# invoked with python3 scan.py [input_file.txt] [output_file.json]
# parameter is a filename for the input file: contain a list of domains to test
# output: JSON dict, keys are the domains that were scanned and the values are dicts with scan results
# just start by printing scan_time everything else added in p2



# structure: main() parses file for each domain
# then have each domain call a scan_domain()
# scan_domain() will contain call all scanner functions i.e. scan_time(), scan_ipv4() etc.



# Part 2: Network Scanners



def scan_domain(domain_list):
    '''
    Calls each individual scanner to retrieve information about each domain
    '''
    results = {}
    for domain in domain_list:
        results[domain] = {}
        results[domain]['scan_time'] = time.time()
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