# write a python program that takes a list of web domains as an input and ouputs a json dict with information about each domain
import time 
import sys
import json
import subprocess
import re
import requests

input_file = sys.argv[1]
output_file = sys.argv[2]

public_dns_resolvers = [
    #'208.67.222.222',
    #'1.1.1.1',
    '8.8.8.8',
    #'8.26.56.26',
    #'9.9.9.9',
    #'94.140.14.14',
    #'185.228.168.9',
    #'76.76.2.0',
    #'76.76.19.19',
    #'129.105.49.1',
    #'74.82.42.42',
    #'205.171.3.65',
    #'193.110.81.0',
    #'147.93.130.20',
    #'51.158.108.203',
]

with open(input_file, 'r') as f:
    domains = f.readlines()
 # domains now a list

 
domain_dict = {}

def add_ipv4_and_ipv6(domain, atype):

    ips = set()

    for server in public_dns_resolvers:
        
        try:
            result = subprocess.check_output(["nslookup", "-type=" + atype, domain.strip(), server.strip()],
                timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
        except subprocess.TimeoutExpired:
            print("timeout, skipping...")
            continue

        regex = ''

        if atype == 'A':
            regex = r'(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}'
        else:
            regex = r'(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))'
        if "Non-authoritative answer:" in result:
            result = result.split("Non-authoritative answer:")[1]
        else:
            parts = result.split('\n\n', 1)
            result = parts[1] if len(parts) > 1 else result
        # i found this regex thing online on a website called ihateregex.io
        for match in re.finditer(regex, result):
            ips.add(match.group(0))
    return sorted(list(ips))

def add_HTTP(domain):
    result = {
        "http_server": None, 
        "insecure_http": False,
        "redirect_to_https": False, 
        "hsts": False,
    }

    try: 
        session = requests.Session()
        session.max_redirects = 10

        # port 80
        response = session.get("http://" + domain, timeout=5)
        result["insecure_http"] = True

        result["http_server"] = response.headers.get("Server", None)


        # redirect check 

        path= []
        for r in response.history: 
            path.append(r.url)
        path.append(response.url)

        for url in path: 
            if url[:8] == "https://":
                result["redirect_to_https"] = True

        if response.url[:8] == "https://":
            if "Strict-Transport-Security" in response.headers:
                result["hsts"] = True

        return result
    except (requests.exceptions.RequestException, requests.exceptions.TooManyRedirects) as e:
        print("error: " + str(e))
        pass
    return result

    

# lots of domain name resolvers, check every one of them and return all the unique ones.  

for domain in domains:
    current_time = time.time()
    domain_dict[domain.strip()] = {
        'scan_time': current_time,
        'ipv4_addresses': add_ipv4_and_ipv6(domain.strip(), 'A'),
        'ipv6_addresses': add_ipv4_and_ipv6(domain.strip(), 'AAAA'),
        'http_server': add_HTTP(domain.strip())['http_server'],
        'insecure_http': add_HTTP(domain.strip())['insecure_http'],
        'redirect_to_https': add_HTTP(domain.strip())['redirect_to_https'],
        'hsts': add_HTTP(domain.strip())['hsts'],

    }


    # is json object a dict? # yes. 
with open(output_file, 'w') as f:
    json.dump(domain_dict, f, sort_keys=True, indent=4)
#
# if required command line tool is missing, do not crash and just skip it

